"""Live packet capture with rotating pcap files, auto-ingested into the
case's evidence pipeline as each rotation completes.

Two capture backends, picked the same way the pcap parser picks a
dissection engine - whichever the machine can actually offer:

  dumpcap   Wireshark's capture engine. Preferred when installed. It does
            the packet copying and the file rotation itself, in C, with a
            small privileged footprint - it is the program Wireshark and
            tshark both shell out to precisely so that the large GUI and
            the large dissector library never need capture privileges.
            Rotation is handled by dumpcap's own ring buffer, so no packet
            is lost at a window boundary the way a Python-side rotation
            can lose one.

  scapy     The pure-Python fallback, used when Wireshark is not
            installed. Every packet crosses into Python to be written,
            which is what limits it on a busy link.

Either way this needs a working packet-capture driver (Npcap on Windows,
libpcap on Linux/macOS) plus elevated privileges to open a network
interface - none of which this module installs or grants. If the
underlying capture can't actually run in the current environment, start()
raises CaptureError; that's the same "explicit, investigator-run, tool
doesn't grant itself privileges" posture as the AI assistant needing its
own API key.

Each rotation window's packets are written to a staging pcap file, then
ingested through the exact same pipeline `netforensic evidence add` +
`analyze` use (EvidenceManager.add -> parse_evidence_item ->
correlate_case -> scan_detections), so a live-captured window becomes a
normal, hashed, traceable piece of case evidence - not a second, less
rigorous path. Nothing captured here is transmitted anywhere; it stays
local to the case, same as every other evidence type.

Because bundled detection rules (core/detections.py) run on every window
the same way they run on every `analyze`, this doubles as a lightweight
live alerting mode: a match against a just-captured window shows up in
recent_events immediately, and the web UI's Live Capture tab surfaces it
as soon as the next status poll picks it up - no separate "watch" command
or extra opt-in needed, since detection scanning is already automatic.
"""

import logging
import re
import subprocess
import tempfile
import threading
import time
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_ROTATE_SECONDS = 30
MAX_RECENT_EVENTS = 50

ENGINE_AUTO = "auto"
ENGINE_DUMPCAP = "dumpcap"
ENGINE_SCAPY = "scapy"
VALID_CAPTURE_ENGINES = (ENGINE_AUTO, ENGINE_DUMPCAP, ENGINE_SCAPY)

# Overrides the backend without threading an argument through every
# caller - the same escape hatch NETFORENSIC_PCAP_ENGINE gives the parser,
# and for the same reason: whether a machine happens to have Wireshark
# installed must not be able to silently change which code path runs.
CAPTURE_ENGINE_ENV = "NETFORENSIC_CAPTURE_ENGINE"

# How often the dumpcap backend looks for a finished rotation file. Well
# under any sane rotate_seconds, so a completed window is picked up
# promptly, but not so tight that idle polling shows up in a profile.
DUMPCAP_POLL_SECONDS = 1.0

# How long to let dumpcap run before deciding it started successfully. It
# fails fast - a bad interface or missing privileges kills it immediately -
# so this only has to outlast process spawn, and reporting dumpcap's own
# error beats reporting a generic failure much later.
DUMPCAP_STARTUP_GRACE_SECONDS = 0.4

# Grace period for dumpcap to flush and close its current file on stop
# before it is killed. A kill here would truncate the final window.
DUMPCAP_STOP_TIMEOUT_SECONDS = 10

# dumpcap reports progress on stderr as "Packets captured: N" (and, on
# some platforms, a bare "Packets: N"). Parsed only to drive the live
# counter in the UI - the authoritative per-window count comes from the
# rotation file itself once it is complete.
_DUMPCAP_PROGRESS = re.compile(r"Packets(?: captured)?:\s*(\d+)")

# dumpcap announces the interface it actually opened, e.g.
# "Capturing on 'Wi-Fi'". Worth capturing because when no --interface is
# given, dumpcap picks one itself, and its choice is frequently a virtual
# or disconnected adapter that yields nothing - a silent failure that
# looks exactly like a quiet network.
_DUMPCAP_INTERFACE = re.compile(r"Capturing on '([^']+)'")

# Consecutive empty rotations before saying the interface is probably
# wrong. One empty window is ordinary on a quiet link; several in a row on
# a link that should have traffic means the wrong adapter was selected.
EMPTY_WINDOWS_BEFORE_WARNING = 3


class CaptureError(Exception):
    """Raised for capture setup/control failures: bad interface, no driver, already running."""


class CaptureSession:
    """The scapy capture backend, and the shared session machinery.

    Everything after start()/stop() - staging, per-window ingestion into
    the case, detection scanning, the status snapshot - is backend-
    independent, so DumpcapCaptureSession inherits it and replaces only
    how packets reach a rotation file. Keeping ingestion in one place is
    what guarantees a window captured by dumpcap becomes exactly the same
    kind of hashed, traceable evidence as one captured by scapy.
    """

    engine = ENGINE_SCAPY

    def __init__(self, case_id, case_dir, case_manager, interface=None, bpf_filter=None, rotate_seconds=DEFAULT_ROTATE_SECONDS):
        self.case_id = case_id
        self.case_dir = Path(case_dir)
        self.case_manager = case_manager
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.rotate_seconds = rotate_seconds

        self._sniffer = None
        self._lock = threading.Lock()
        self._writer = None
        self._current_file = None
        self._staging_dir = Path(tempfile.mkdtemp(prefix="netforensic_capture_"))
        self._window_started_at = None
        self._window_packet_count = 0
        self._window_byte_count = 0
        self._window_protocols = Counter()
        self._total_packet_count = 0
        self._started_at = None
        self._running = False
        self._rotation_index = 0
        self.recent_events = deque(maxlen=MAX_RECENT_EVENTS)

    def start(self):
        with self._lock:
            if self._running:
                raise CaptureError("Capture is already running for this case.")
            try:
                from scapy.all import AsyncSniffer
            except ImportError as e:
                raise CaptureError("scapy is not installed - install the [pcap] extra.") from e

            self._open_new_window()
            self._sniffer = AsyncSniffer(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._on_packet,
                store=False,
            )
            try:
                self._sniffer.start()
            except Exception as e:
                raise CaptureError(
                    f"Failed to start capture on interface '{self.interface}': {e}. "
                    "Live capture needs a packet-capture driver (Npcap on Windows, libpcap on "
                    "Linux/macOS) and elevated privileges - this tool cannot grant those itself; "
                    "run it yourself with the appropriate driver installed and privileges."
                ) from e
            self._started_at = datetime.now(timezone.utc)
            self._running = True

    def stop(self):
        if not self._running:
            return
        with self._lock:
            self._running = False
        # Stop the sniffer *outside* the lock: if its own capture thread is
        # mid-callback waiting on this same lock (see _on_packet), stopping
        # while holding the lock could deadlock - the sniffer thread would
        # never get the lock back to notice it should exit.
        try:
            self._sniffer.stop()
        except Exception as e:
            logger.warning(f"Error stopping sniffer: {e}")
        with self._lock:
            self._rotate(final=True)

    def _on_packet(self, packet):
        with self._lock:
            if not self._running:
                return
            try:
                self._writer.write(packet)
            except Exception as e:
                logger.warning(f"Failed to write captured packet: {e}")
                return
            self._window_packet_count += 1
            self._total_packet_count += 1
            try:
                self._window_byte_count += len(packet)
            except Exception:
                pass
            self._window_protocols[_protocol_name(packet)] += 1

            if time.time() - self._window_started_at >= self.rotate_seconds:
                self._rotate()

    def _open_new_window(self):
        from scapy.utils import PcapWriter

        self._rotation_index += 1
        self._current_file = self._staging_dir / f"window-{self._rotation_index:04d}.pcap"
        self._writer = PcapWriter(str(self._current_file))
        self._window_started_at = time.time()
        self._window_packet_count = 0
        self._window_byte_count = 0
        self._window_protocols = Counter()

    def _rotate(self, final=False):
        """Caller must hold self._lock."""
        finished_file = self._current_file
        finished_count = self._window_packet_count
        try:
            self._writer.close()
        except Exception:
            pass

        if not final:
            self._open_new_window()

        if finished_count > 0:
            threading.Thread(target=self._ingest, args=(finished_file, finished_count), daemon=True).start()

    def _ingest(self, pcap_path, packet_count):
        """Runs on its own thread, one per rotation, so a slow parse/
        correlate pass never blocks live capture of the next window."""
        from netforensicai.core.case import CaseError
        from netforensicai.core.correlation import correlate_case
        from netforensicai.core.detections import scan_case as scan_detections
        from netforensicai.core.evidence import EvidenceError, EvidenceManager
        from netforensicai.core.pipeline import parse_evidence_item
        from netforensicai.core.store import locked_store

        try:
            self.case_manager.load(self.case_id)
        except CaseError as e:
            self._record_event({"error": f"Case not found during ingestion: {e}"})
            return

        try:
            evidence_manager = EvidenceManager(self.case_dir)
            evidence = evidence_manager.add(pcap_path, case_id=self.case_id)
            self.case_manager.register_evidence(self.case_id, evidence.evidence_id)
        except EvidenceError as e:
            self._record_event({"error": f"Failed to ingest capture window: {e}"})
            return
        finally:
            try:
                Path(pcap_path).unlink(missing_ok=True)
            except Exception:
                pass

        with locked_store(self.case_dir) as store:
            event_count, entity_count, error = parse_evidence_item(
                evidence, self.case_dir, self.case_manager, self.case_id, store
            )
            if error:
                self._record_event({"evidence_id": evidence.evidence_id, "error": error})
                return
            # Live capture is the densest source this platform has, and the
            # two defaults that suit a static evidence file are actively
            # wrong here. A 300-second window over a busy link puts nearly
            # every event within reach of every other, and almost none of
            # those pairs share an entity - so the weak `possible_relation-
            # ship` tier alone can exhaust the link budget every rotation
            # while saying nothing. Correlate over the rotation period and
            # keep shared-entity links only.
            correlate_case(
                store,
                time_window_seconds=max(self.rotate_seconds, 1),
                include_possible=False,
            )
            # Bundled detection rules (core/detections.py) run automatically
            # here too, same as `analyze` - a full case rescan each window,
            # filtered down to just this window's evidence so the live feed
            # surfaces "this window triggered N alerts" without re-showing
            # every prior window's hits on every rotation.
            all_detections = scan_detections(store)
            new_detections = [d for d in all_detections if d["evidence_id"] == evidence.evidence_id]

        self._record_event(
            {
                "evidence_id": evidence.evidence_id,
                "packet_count": packet_count,
                "event_count": event_count,
                "entity_count": entity_count,
                "new_detections": [
                    {**d, "detected_at": d["detected_at"].isoformat() if d["detected_at"] else None}
                    for d in new_detections
                ],
            }
        )

    def _record_event(self, data):
        data = dict(data)
        data["at"] = datetime.now(timezone.utc).isoformat()
        self.recent_events.append(data)
        if "error" in data:
            logger.warning(f"Capture ingestion error for case {self.case_id}: {data['error']}")

    def snapshot(self):
        with self._lock:
            elapsed = (datetime.now(timezone.utc) - self._started_at).total_seconds() if self._started_at else 0
            window_elapsed = time.time() - self._window_started_at if self._window_started_at else 0
            return {
                "running": self._running,
                "engine": self.engine,
                "interface": self.interface,
                # What is actually being captured, which differs from
                # `interface` whenever none was requested and the backend
                # picked one. The UI shows this so a capture on the wrong
                # adapter is visible rather than silently empty.
                "capturing_on": getattr(self, "_capturing_on", None) or self.interface,
                "consecutive_empty_windows": getattr(self, "_consecutive_empty_windows", 0),
                "filter": self.bpf_filter,
                "rotate_seconds": self.rotate_seconds,
                "started_at": self._started_at.isoformat() if self._started_at else None,
                "elapsed_seconds": elapsed,
                "total_packet_count": self._total_packet_count,
                "window_packet_count": self._window_packet_count,
                "window_byte_count": self._window_byte_count,
                "window_protocols": dict(self._window_protocols),
                "window_elapsed_seconds": window_elapsed,
                "recent_events": list(self.recent_events),
            }


class DumpcapCaptureSession(CaptureSession):
    """Live capture backed by dumpcap, Wireshark's own capture engine.

    dumpcap does the packet copying and the rotation in C: `-b duration:N`
    tells it to start a new file every N seconds, and it names each one
    <base>_NNNNN_YYYYMMDDHHMMSS.pcap. This process never touches a packet
    on the capture path at all - it watches the staging directory and
    hands each *finished* file to the same ingestion the scapy backend
    uses.

    That division matters for evidence quality, not just throughput. A
    Python-side rotation has to stop writing, close the file and reopen a
    new one while packets keep arriving, so packets can be dropped at
    every window boundary; dumpcap's ring buffer switches files without
    that gap. It is also the smaller privileged surface: dumpcap is the
    one small program Wireshark itself isolates capture privileges into.
    """

    engine = ENGINE_DUMPCAP

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._process = None
        self._watcher = None
        self._stderr_reader = None
        self._ingested = set()
        # Packets in windows dumpcap has already finished and handed over,
        # counted from the rotation files themselves. Kept separate from
        # the live figure because dumpcap's progress output is cumulative
        # for the whole session, not per-file - see _refresh_counts.
        self._rotated_packet_count = 0
        self._live_packet_count = 0
        # The interface dumpcap actually opened, which is only the same as
        # self.interface when one was explicitly requested.
        self._capturing_on = None
        self._consecutive_empty_windows = 0

    def start(self):
        from netforensicai.integrations import wireshark

        with self._lock:
            if self._running:
                raise CaptureError("Capture is already running for this case.")
            binary = wireshark.dumpcap_path()
            if binary is None:
                raise CaptureError(
                    "dumpcap was not found - install Wireshark, or use the scapy engine."
                )

            # -w gives the rotation base name; dumpcap appends its own
            # index and timestamp to each file it actually writes.
            self._current_file = self._staging_dir / "window.pcap"
            argv = [
                binary,
                "-w",
                str(self._current_file),
                "-b",
                f"duration:{int(self.rotate_seconds)}",
            ]
            if self.interface:
                argv += ["-i", str(self.interface)]
            if self.bpf_filter:
                # A capture (BPF) filter, not a display filter: dumpcap has
                # no dissectors, so this is the same -f syntax the existing
                # scapy backend already takes.
                argv += ["-f", self.bpf_filter]

            try:
                self._process = subprocess.Popen(
                    argv,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
            except OSError as e:
                raise CaptureError(f"Failed to launch dumpcap: {e}") from e

            # dumpcap exits almost immediately when the interface is bad or
            # privileges are missing. Give it that moment and surface its
            # own message, which names the actual problem far better than a
            # generic "capture failed" would.
            time.sleep(DUMPCAP_STARTUP_GRACE_SECONDS)
            if self._process.poll() is not None:
                detail = (self._process.stderr.read() or "").strip().splitlines()
                raise CaptureError(
                    f"dumpcap exited immediately: {detail[-1] if detail else 'no output'}. "
                    "Live capture needs a packet-capture driver (Npcap on Windows, libpcap "
                    "on Linux/macOS) and elevated privileges - this tool cannot grant those "
                    "itself; run it yourself with the driver installed and privileges held."
                )

            self._window_started_at = time.time()
            self._started_at = datetime.now(timezone.utc)
            self._running = True

        self._watcher = threading.Thread(target=self._watch_rotations, daemon=True)
        self._watcher.start()
        self._stderr_reader = threading.Thread(target=self._read_progress, daemon=True)
        self._stderr_reader.start()

    def stop(self):
        if not self._running:
            return
        with self._lock:
            self._running = False
        if self._process is not None and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=DUMPCAP_STOP_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                logger.warning("dumpcap did not exit on terminate; killing it.")
                self._process.kill()
                self._process.wait()
        if self._watcher is not None:
            self._watcher.join(timeout=DUMPCAP_POLL_SECONDS * 3)
        # dumpcap has exited, so every file it left behind is complete -
        # including the one it was still writing, which the sweep was
        # deliberately holding back while the capture was live.
        self._sweep()

    def _rotation_files(self):
        """Finished rotation files, oldest first.

        While the capture is running the newest file is the one dumpcap is
        still writing, so it is excluded: ingesting a half-written pcap
        would put a truncated capture into the case as though it were a
        complete window.
        """
        files = sorted(self._staging_dir.glob("window_*.pcap"))
        return files if not self._running else files[:-1]

    def _watch_rotations(self):
        while self._running:
            time.sleep(DUMPCAP_POLL_SECONDS)
            try:
                self._sweep()
            except Exception as e:
                logger.warning(f"Error while sweeping dumpcap rotations: {e}")

    def _sweep(self):
        for path in self._rotation_files():
            if path in self._ingested:
                continue
            self._ingested.add(path)
            packet_count = self._count_packets(path)
            if packet_count == 0:
                # dumpcap writes a header-only file for a window in which
                # nothing matched the capture filter. That is not evidence
                # of anything, and ingesting it would fill the case with
                # empty evidence items.
                path.unlink(missing_ok=True)
                self._note_empty_window()
                continue
            with self._lock:
                self._consecutive_empty_windows = 0
                self._rotation_index += 1
                self._rotated_packet_count += packet_count
                self._window_started_at = time.time()
                self._refresh_counts()
            # _ingest deletes the file when it is done with it, and runs on
            # its own thread so a slow parse never stalls the sweep.
            threading.Thread(target=self._ingest, args=(path, packet_count), daemon=True).start()

    def _note_empty_window(self):
        """Surface the failure mode that looks exactly like success.

        A capture on the wrong adapter runs happily forever and produces
        nothing, which is indistinguishable from a genuinely idle link
        unless someone says so. Reported once, on crossing the threshold,
        rather than every rotation - a quiet link should not become a log
        firehose.
        """
        with self._lock:
            self._consecutive_empty_windows += 1
            count = self._consecutive_empty_windows
            interface = self._capturing_on or self.interface or "(dumpcap's default)"
        if count != EMPTY_WINDOWS_BEFORE_WARNING:
            return
        detail = f" and capture filter '{self.bpf_filter}'" if self.bpf_filter else ""
        message = (
            f"{count} consecutive capture windows on interface '{interface}'{detail} "
            "contained no packets. If traffic is expected, the interface is probably "
            "wrong - stop the capture and check `netforensic capture --list-interfaces`."
        )
        logger.warning(message)
        self._record_event({"warning": message})

    @staticmethod
    def _count_packets(path):
        from netforensicai.integrations import wireshark

        try:
            return wireshark.count_packets(path)
        except wireshark.WiresharkError as e:
            logger.warning(f"Could not count packets in '{path}': {e}")
            return 0

    def _refresh_counts(self):
        """Recompute the reported counters. Caller must hold self._lock.

        dumpcap's progress output counts packets for the WHOLE capture
        session, not for the file it currently has open, so it cannot be
        used as the window count directly - doing so reports the running
        total in the window field and makes the window appear never to
        reset. The window is the difference between what dumpcap has seen
        and what has already been rotated away.

        The rotated sum is authoritative for the total, so if progress
        parsing yields nothing (a platform whose dumpcap reports
        differently) the totals stay correct and only the live in-window
        number goes missing.
        """
        self._total_packet_count = max(self._live_packet_count, self._rotated_packet_count)
        self._window_packet_count = max(0, self._live_packet_count - self._rotated_packet_count)

    def _read_progress(self):
        """Feed the live counter from dumpcap's own progress output.

        Best-effort: every count that reaches the case comes from the
        rotation files themselves, so a parsing miss costs the live number
        in the UI, never any evidence.
        """
        stream = self._process.stderr if self._process else None
        if stream is None:
            return
        try:
            # Text mode uses universal newlines, so dumpcap's carriage-
            # return progress updates each arrive as their own line here.
            for line in stream:
                match = _DUMPCAP_PROGRESS.search(line)
                if match:
                    with self._lock:
                        self._live_packet_count = int(match.group(1))
                        self._refresh_counts()
                    continue
                opened = _DUMPCAP_INTERFACE.search(line)
                if opened:
                    with self._lock:
                        self._capturing_on = opened.group(1)
                    if not self.interface:
                        # No interface was requested, so dumpcap chose. Say
                        # which one out loud: its default is often a virtual
                        # or disconnected adapter, and a capture that yields
                        # nothing because of that is indistinguishable from a
                        # quiet network unless the name is visible.
                        logger.info(
                            f"No interface requested; dumpcap selected '{opened.group(1)}'. "
                            "If that is not the link you meant to capture, stop and pass "
                            "--interface (see --list-interfaces)."
                        )
                elif line.strip():
                    logger.debug(f"dumpcap: {line.strip()}")
        except Exception:
            pass


def _protocol_name(packet):
    try:
        from scapy.all import ARP, DNS, ICMP, TCP, UDP

        if packet.haslayer(DNS):
            return "DNS"
        if packet.haslayer(TCP):
            return "TCP"
        if packet.haslayer(UDP):
            return "UDP"
        if packet.haslayer(ICMP):
            return "ICMP"
        if packet.haslayer(ARP):
            return "ARP"
    except Exception:
        pass
    return "other"


_SESSIONS = {}
_SESSIONS_LOCK = threading.Lock()


def resolve_capture_engine(engine=None):
    """Return the capture backend to use: "dumpcap" or "scapy".

    Same shape as the pcap parser's engine resolution, and deliberately
    the same posture: "auto" prefers dumpcap when it is installed, but a
    specifically requested backend that is missing is an error rather than
    a silent substitution - an analyst who asked for dumpcap did so for a
    reason, usually because scapy was dropping packets on a busy link.
    """
    import os

    from netforensicai.integrations import wireshark

    requested = (engine or os.environ.get(CAPTURE_ENGINE_ENV) or ENGINE_AUTO).strip().lower()
    if requested not in VALID_CAPTURE_ENGINES:
        raise CaptureError(
            f"Unknown capture engine '{requested}'. Choose one of: {', '.join(VALID_CAPTURE_ENGINES)}."
        )
    if requested == ENGINE_DUMPCAP:
        if wireshark.dumpcap_path() is None:
            raise CaptureError(
                "The dumpcap engine was requested but dumpcap was not found. Install Wireshark, "
                "or set NETFORENSIC_DUMPCAP to its executable."
            )
        return ENGINE_DUMPCAP
    if requested == ENGINE_SCAPY:
        return ENGINE_SCAPY
    return ENGINE_DUMPCAP if wireshark.dumpcap_path() is not None else ENGINE_SCAPY


def list_interfaces():
    """Capture interfaces as [{"name", "description"}], newest-capable
    source first.

    dumpcap is preferred because it reports the same interface identifiers
    the Wireshark GUI shows *and* a human description. scapy's
    get_if_list() returns bare \\Device\\NPF_{GUID} strings on Windows,
    which an analyst cannot match to a physical NIC - so the scapy
    fallback fills description with an empty string rather than inventing
    one.
    """
    from netforensicai.integrations import wireshark

    if wireshark.dumpcap_path() is not None:
        try:
            return wireshark.list_interfaces()
        except wireshark.WiresharkError as e:
            logger.warning(f"dumpcap could not list interfaces, falling back to scapy: {e}")

    from scapy.all import get_if_list

    return [{"name": name, "description": ""} for name in get_if_list()]


def start_capture(
    case_id,
    case_dir,
    case_manager,
    interface=None,
    bpf_filter=None,
    rotate_seconds=DEFAULT_ROTATE_SECONDS,
    engine=None,
):
    with _SESSIONS_LOCK:
        existing = _SESSIONS.get(case_id)
        if existing is not None and existing.snapshot()["running"]:
            raise CaptureError(f"Capture already running for case {case_id}.")
        selected = resolve_capture_engine(engine)
        session_class = DumpcapCaptureSession if selected == ENGINE_DUMPCAP else CaptureSession
        session = session_class(case_id, case_dir, case_manager, interface, bpf_filter, rotate_seconds)
        session.start()
        _SESSIONS[case_id] = session
        return session


def stop_capture(case_id):
    with _SESSIONS_LOCK:
        session = _SESSIONS.get(case_id)
        if session is None:
            raise CaptureError(f"No capture session found for case {case_id}.")
    session.stop()
    return session


def get_session(case_id):
    with _SESSIONS_LOCK:
        return _SESSIONS.get(case_id)
