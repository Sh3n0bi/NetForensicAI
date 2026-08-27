"""Live packet capture with rotating pcap files, auto-ingested into the
case's evidence pipeline as each rotation completes.

Requires the [pcap] extra (scapy) AND, unlike file parsing, a working
packet-capture driver (Npcap on Windows, libpcap on Linux/macOS) plus
elevated privileges to open a network interface - none of which this
module installs or grants. If the underlying sniffer can't actually
capture in the current environment, start() raises CaptureError; that's
the same "explicit, investigator-run, tool doesn't grant itself
privileges" posture as the AI assistant needing its own API key.

Each rotation window's packets are written to a staging pcap file, then
ingested through the exact same pipeline `netforensic evidence add` +
`analyze` use (EvidenceManager.add -> parse_evidence_item ->
correlate_case), so a live-captured window becomes a normal, hashed,
traceable piece of case evidence - not a second, less rigorous path.
Nothing captured here is transmitted anywhere; it stays local to the
case, same as every other evidence type.
"""

import logging
import tempfile
import threading
import time
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_ROTATE_SECONDS = 30
MAX_RECENT_EVENTS = 50


class CaptureError(Exception):
    """Raised for capture setup/control failures: bad interface, no driver, already running."""


class CaptureSession:
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
            correlate_case(store)

        self._record_event(
            {
                "evidence_id": evidence.evidence_id,
                "packet_count": packet_count,
                "event_count": event_count,
                "entity_count": entity_count,
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
                "interface": self.interface,
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


def list_interfaces():
    from scapy.all import get_if_list

    return get_if_list()


def start_capture(case_id, case_dir, case_manager, interface=None, bpf_filter=None, rotate_seconds=DEFAULT_ROTATE_SECONDS):
    with _SESSIONS_LOCK:
        existing = _SESSIONS.get(case_id)
        if existing is not None and existing.snapshot()["running"]:
            raise CaptureError(f"Capture already running for case {case_id}.")
        session = CaptureSession(case_id, case_dir, case_manager, interface, bpf_filter, rotate_seconds)
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
