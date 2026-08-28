"""Discovery of, and thin wrappers around, the Wireshark command-line suite.

Wireshark ships several binaries this platform can use, all optional:

  tshark    - the dissection engine. Ships ~3000 protocol dissectors, where
              the bundled scapy parser hand-implements seven analyses. When
              tshark is present the pcap parser prefers it (see
              parsers/pcap_tshark.py); when it isn't, nothing changes.
  dumpcap   - the capture engine tshark and the GUI both shell out to.
              Handles ring buffers and file rotation itself, in C, which is
              what makes it a better live-capture backend than the scapy
              sniffer (see core/capture.py).
  Wireshark - the GUI, for the "show me the packets behind this finding"
              pivot (see open_gui).

DISCOVERY IS DELIBERATELY CACHED AND OVERRIDABLE. Analysts run this on
locked-down DFIR workstations where Wireshark is installed somewhere
non-standard, so PATH lookup alone is not enough - hence the per-platform
install directories and the NETFORENSIC_WIRESHARK_DIR / NETFORENSIC_TSHARK
escape hatches. Nothing here ever installs, downloads, or elevates
anything: if the tooling isn't already on the machine, callers fall back.

Every invocation passes an argument *list*, never a shell string. Display
filters reach this module from analyst input and from evidence-derived
values, and handing either to a shell would turn a filter into a command.
"""

import json
import logging
import os
import platform
import re
import shutil
import subprocess
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

# tshark's documented exit codes. 4 is the one that matters: it means the
# command line - which for us means the display filter - was invalid, as
# opposed to 2 (capture file open failed) or 3 (file doesn't exist or is
# unreadable). Distinguishing them is what lets validate_display_filter()
# check a filter without needing a capture file to check it against.
TSHARK_EXIT_INVALID_ARGUMENTS = 4

# Ceiling on how long a single tshark invocation may run. Parsing streams
# and has no timeout (a multi-gigabyte capture legitimately takes minutes);
# these apply to the short, bounded calls - version probes, filter
# validation, slice extraction.
PROBE_TIMEOUT_SECONDS = 20
SLICE_TIMEOUT_SECONDS = 600

# Where Wireshark installs itself when nothing put it on PATH. Windows is
# the common case: the installer does not add its directory to PATH, so on
# a stock Windows analyst workstation shutil.which("tshark") fails even
# though Wireshark is sitting right there.
_INSTALL_DIRS = {
    "Windows": (
        "C:\\Program Files\\Wireshark",
        "C:\\Program Files (x86)\\Wireshark",
    ),
    "Darwin": (
        "/Applications/Wireshark.app/Contents/MacOS",
        "/opt/homebrew/bin",
        "/usr/local/bin",
    ),
    "Linux": (
        "/usr/bin",
        "/usr/local/bin",
        "/usr/sbin",
        "/snap/bin",
    ),
}

# Basename (no extension) of each tool, and the environment variable that
# overrides discovery for it.
_TOOLS = {
    "tshark": "NETFORENSIC_TSHARK",
    "dumpcap": "NETFORENSIC_DUMPCAP",
    "wireshark": "NETFORENSIC_WIRESHARK",
}

_cache = {}
_cache_lock = threading.Lock()


class WiresharkError(Exception):
    """Raised when a Wireshark binary is needed but missing, or a call to one fails."""


def reset_cache():
    """Forget discovered paths. Called by tests, and whenever the configured
    install directory changes at runtime."""
    with _cache_lock:
        _cache.clear()


def _candidate_dirs():
    """Directories to search, most specific first. An explicitly configured
    directory wins over the platform defaults so an analyst can point at a
    portable or parallel install without touching PATH."""
    configured = os.environ.get("NETFORENSIC_WIRESHARK_DIR")
    dirs = [configured] if configured else []
    dirs.extend(_INSTALL_DIRS.get(platform.system(), ()))
    return dirs


def find_tool(name):
    """Absolute path to a Wireshark binary, or None if it isn't installed.

    Order: explicit env override -> PATH -> known install directories.
    Cached because this is called per parse, per capture rotation and per
    web request, and a failed lookup walking several directories is not
    free.
    """
    with _cache_lock:
        if name in _cache:
            return _cache[name]

    override = os.environ.get(_TOOLS.get(name, ""))
    resolved = None
    if override and Path(override).is_file():
        resolved = str(Path(override))
    else:
        found = shutil.which(name)
        if found:
            resolved = found
        else:
            # The GUI binary is capitalized on Windows and macOS.
            executable = f"{name}.exe" if platform.system() == "Windows" else name
            alternatives = [executable, executable[0].upper() + executable[1:]]
            for directory in _candidate_dirs():
                for candidate_name in alternatives:
                    candidate = Path(directory) / candidate_name
                    if candidate.is_file():
                        resolved = str(candidate)
                        break
                if resolved:
                    break

    with _cache_lock:
        _cache[name] = resolved
    return resolved


def tshark_path():
    return find_tool("tshark")


def dumpcap_path():
    return find_tool("dumpcap")


def gui_path():
    return find_tool("wireshark")


def available():
    """True when tshark is usable - the single check callers gate on before
    preferring the Wireshark path over the built-in one."""
    return tshark_path() is not None


def _run(argv, timeout, check=True):
    """Run a Wireshark binary and return the CompletedProcess.

    Output is decoded leniently: tshark emits interface names and packet
    summaries in the host locale's encoding, which is routinely not UTF-8
    on Windows, and a mis-decoded byte in an interface description must
    not take down an investigation.
    """
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            timeout=timeout,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired as e:
        raise WiresharkError(f"{Path(argv[0]).name} timed out after {timeout}s") from e
    except OSError as e:
        raise WiresharkError(f"Failed to run {argv[0]}: {e}") from e
    if check and completed.returncode != 0:
        message = (completed.stderr or completed.stdout or "").strip().splitlines()
        detail = message[0] if message else f"exit code {completed.returncode}"
        raise WiresharkError(f"{Path(argv[0]).name} failed: {detail}")
    return completed


def version():
    """Version string of the discovered tshark, e.g. '4.6.8', or None."""
    binary = tshark_path()
    if binary is None:
        return None
    try:
        completed = _run([binary, "--version"], PROBE_TIMEOUT_SECONDS)
    except WiresharkError:
        return None
    match = re.search(r"(\d+\.\d+\.\d+)", completed.stdout or "")
    return match.group(1) if match else None


def status():
    """Everything the CLI's `wireshark status` and the web UI's capability
    banner need, in one call: which tools were found, and what version."""
    return {
        "available": available(),
        "version": version(),
        "tshark": tshark_path(),
        "dumpcap": dumpcap_path(),
        "gui": gui_path(),
    }


# --- Display filters ---------------------------------------------------


def validate_display_filter(display_filter):
    """Return (is_valid, error_message) for a Wireshark display filter.

    Checked by handing the filter to tshark itself rather than by
    reimplementing its grammar - the filter language has thousands of
    protocol fields and its own type rules, and an approximation here would
    reject valid analyst filters. tshark parses -Y *before* opening the
    capture file, so a path that cannot be read is enough to get a verdict
    without needing a capture: exit code 4 means the filter is bad,
    anything else means it parsed and only the file was the problem.
    """
    if not display_filter or not display_filter.strip():
        return False, "Display filter is empty."
    binary = tshark_path()
    if binary is None:
        return False, "tshark is not installed, so display filters cannot be validated."
    completed = _run(
        [binary, "-Y", display_filter, "-r", os.devnull],
        PROBE_TIMEOUT_SECONDS,
        check=False,
    )
    if completed.returncode == TSHARK_EXIT_INVALID_ARGUMENTS:
        lines = (completed.stderr or "").strip().splitlines()
        return False, lines[0].replace("tshark: ", "") if lines else "Invalid display filter."
    return True, None


def _address_field(address):
    """ip.addr only matches IPv4 and ipv6.addr only matches IPv6, so a
    filter built with the wrong one silently matches nothing - which reads
    to the analyst as "the evidence isn't there" rather than "the filter is
    wrong". A colon is unambiguous here: an IPv4 literal never has one."""
    return "ipv6.addr" if ":" in str(address) else "ip.addr"


def _quote(value):
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def filter_for_event(event):
    """Build the narrowest display filter that isolates one Event's packets.

    Prefers exact frame numbers, which both pcap parsers record in
    raw_event_reference - that pins the pivot to the precise packets the
    finding was derived from, not merely to traffic that looks like it.
    Falls back to the flow tuple, then to whatever single identifying
    detail the event carries. Returns None when the event has nothing to
    pivot on, e.g. an event from a non-pcap evidence source.
    """
    reference = event.raw_event_reference or {}

    numbers = reference.get("packet_numbers")
    if not numbers and reference.get("packet_number") is not None:
        numbers = [reference["packet_number"]]
    if numbers:
        unique = sorted({int(n) for n in numbers})
        if len(unique) == 1:
            return f"frame.number == {unique[0]}"
        # `in {..}` keeps a carved-file event's hundreds of frame numbers to
        # a single term instead of hundreds of ORs, which Wireshark's own
        # filter bar handles far better. The commas are required - a
        # space-separated set parses as a range expression and is rejected.
        return "frame.number in {" + ", ".join(str(n) for n in unique) + "}"

    terms = []
    for address in (event.src_ip, event.dst_ip):
        if address:
            terms.append(f"{_address_field(address)} == {address}")

    transport = (event.protocol or "").lower()
    if transport in ("tcp", "udp"):
        for port in (event.src_port, event.dst_port):
            if port is not None:
                terms.append(f"{transport}.port == {port}")

    if terms:
        return " && ".join(terms)

    if event.domain:
        return (
            f"dns.qry.name == {_quote(event.domain)} || "
            f"http.host == {_quote(event.domain)} || "
            f"tls.handshake.extensions_server_name == {_quote(event.domain)}"
        )
    if event.url:
        return f"http.request.full_uri == {_quote(event.url)}"
    return None


# --- Slice extraction and GUI pivot ------------------------------------


def extract_slice(pcap_path, display_filter, output_path):
    """Write the packets matching display_filter to a new pcap at
    output_path, and return (path, packet_count).

    This is what makes a filter *evidentiary* rather than just a view: the
    slice is a real capture file, so it goes back through the normal
    EvidenceManager.add path, gets hashed, and stays traceable like any
    other evidence item - rather than being a screenshot of a filtered GUI.
    """
    binary = tshark_path()
    if binary is None:
        raise WiresharkError("tshark is not installed - cannot extract a filtered slice.")
    valid, error = validate_display_filter(display_filter)
    if not valid:
        raise WiresharkError(error)

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _run(
        [binary, "-r", str(pcap_path), "-Y", display_filter, "-w", str(output_path)],
        SLICE_TIMEOUT_SECONDS,
    )
    if not output_path.exists():
        raise WiresharkError("tshark reported success but produced no output file.")
    return output_path, count_packets(output_path)


def count_packets(pcap_path):
    """Packet count of a capture file. Returns 0 for an empty capture - an
    empty result is a valid answer ("nothing matched that filter"), not an
    error the caller should have to distinguish."""
    binary = tshark_path()
    if binary is None:
        raise WiresharkError("tshark is not installed.")
    completed = _run(
        [binary, "-r", str(pcap_path), "-T", "fields", "-e", "frame.number"],
        SLICE_TIMEOUT_SECONDS,
        check=False,
    )
    if completed.returncode != 0:
        return 0
    return sum(1 for line in (completed.stdout or "").splitlines() if line.strip())


def export_objects(pcap_path, protocol, output_dir):
    """Run tshark's object export for one protocol into output_dir.

    Recovers complete transferred files from reassembled streams, which is
    categorically better evidence than magic-byte carving: the dissector
    knows where the object actually begins and ends rather than inferring
    it. Returns the list of files written. Protocols an older tshark does
    not support raise WiresharkError so the caller can skip just that one.
    """
    binary = tshark_path()
    if binary is None:
        raise WiresharkError("tshark is not installed.")
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    _run(
        [binary, "-r", str(pcap_path), "-q", "--export-objects", f"{protocol},{output_dir}"],
        SLICE_TIMEOUT_SECONDS,
    )
    return sorted(path for path in output_dir.iterdir() if path.is_file())


def open_gui(pcap_path, display_filter=None):
    """Launch the Wireshark GUI on a capture, optionally pre-filtered, and
    return the argv it was launched with.

    Fire-and-forget by design: the GUI is a long-running interactive
    program the analyst drives, so this returns as soon as it has been
    spawned rather than waiting for it to exit. Raises WiresharkError if
    the GUI isn't installed, so the caller can offer gui_command() for the
    analyst to run elsewhere instead.
    """
    binary = gui_path()
    if binary is None:
        raise WiresharkError(
            "The Wireshark GUI was not found. Install Wireshark, or set "
            "NETFORENSIC_WIRESHARK to its executable."
        )
    pcap_path = Path(pcap_path)
    if not pcap_path.is_file():
        raise WiresharkError(f"Capture file not found: {pcap_path}")

    argv = [binary, "-r", str(pcap_path)]
    if display_filter:
        valid, error = validate_display_filter(display_filter)
        if not valid:
            raise WiresharkError(error)
        argv += ["-Y", display_filter]
    try:
        subprocess.Popen(
            argv,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as e:
        raise WiresharkError(f"Failed to launch Wireshark: {e}") from e
    return argv


def gui_command(pcap_path, display_filter=None):
    """The equivalent command line as a string, for surfacing in a UI that
    should not launch a desktop GUI on the analyst's behalf - see the web
    API's pivot endpoint, which hands this back instead of spawning."""
    parts = [gui_path() or "wireshark", "-r", str(pcap_path)]
    if display_filter:
        parts += ["-Y", display_filter]
    return " ".join(_shell_quote(p) for p in parts)


def _shell_quote(value):
    return value if re.fullmatch(r"[\w./:\\-]+", value) else '"' + value.replace('"', '\\"') + '"'


# --- Interfaces --------------------------------------------------------


def list_interfaces():
    """Capture interfaces as reported by dumpcap: a list of
    {"name", "description"}.

    Preferred over scapy's get_if_list() because dumpcap reports the same
    interface identifiers the Wireshark GUI shows and includes human
    descriptions - on Windows scapy returns raw \\Device\\NPF_{GUID}
    strings that an analyst cannot match to a physical NIC.
    """
    binary = dumpcap_path()
    if binary is None:
        raise WiresharkError("dumpcap is not installed.")
    completed = _run([binary, "-D"], PROBE_TIMEOUT_SECONDS)
    interfaces = []
    for line in (completed.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        # Format: "1. \Device\NPF_{GUID} (Ethernet)"
        match = re.match(r"^\d+\.\s+(\S+)(?:\s+\((.*)\))?$", line)
        if match:
            interfaces.append({"name": match.group(1), "description": match.group(2) or ""})
    return interfaces


# --- Streaming dissection ----------------------------------------------


def iter_dissected_packets(pcap_path, fields, display_filter=None, extra_args=()):
    """Yield one dict of {field_name: [values]} per packet, streaming.

    Uses tshark's Elasticsearch-bulk output (-T ek), which is
    newline-delimited JSON: one object per packet, emitted as tshark reads,
    with absent fields omitted rather than blank. That matters for two
    reasons. Streaming keeps peak memory flat on the multi-gigabyte
    captures this platform targets - the same reason the scapy parser
    streams. And unlike `-T fields`, there is no separator character that
    could also occur inside a dissected value, so a hostile hostname or URI
    in the evidence cannot shift the columns and corrupt parsing.

    Raises WiresharkError if tshark cannot start or rejects the filter; a
    *mid-stream* failure (a truncated capture) is logged and ends
    iteration, keeping the packets already read - the same posture as the
    scapy parser's handling of a killed tcpdump.
    """
    binary = tshark_path()
    if binary is None:
        raise WiresharkError("tshark is not installed.")

    # -n disables name resolution: it would otherwise issue reverse-DNS
    # lookups for addresses found in the evidence, which both leaks the
    # investigation to the network and makes parsing wall-clock unbounded.
    argv = [binary, "-r", str(pcap_path), "-T", "ek", "-n"]
    if display_filter:
        argv += ["-Y", display_filter]
    for field in fields:
        argv += ["-e", field]
    argv.extend(extra_args)

    try:
        process = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
    except OSError as e:
        raise WiresharkError(f"Failed to run tshark: {e}") from e

    yielded = 0
    drained = False
    try:
        for line in process.stdout:
            line = line.strip()
            # -T ek interleaves an {"index": ...} control line before each
            # packet line; only the packet lines carry "layers".
            if not line or '"layers"' not in line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            layers = record.get("layers")
            if isinstance(layers, dict):
                yielded += 1
                yield layers
        drained = True
    finally:
        stderr = ""
        try:
            if process.stdout:
                process.stdout.close()
            if process.stderr:
                stderr = process.stderr.read() or ""
                process.stderr.close()
        except Exception:
            pass
        returncode = process.poll()
        if returncode is None:
            # The consumer abandoned the generator part-way (a `break`, or
            # an exception upstream). Without this, tshark would keep
            # dissecting a multi-gigabyte capture into a closed pipe.
            process.kill()
            returncode = process.wait()
        if not drained:
            # The consumer abandoned this generator, so tshark's exit code
            # is a consequence of the kill above, not a fact about the
            # capture. Reporting it would turn "the caller stopped early"
            # into a spurious parse failure.
            return
        if returncode == TSHARK_EXIT_INVALID_ARGUMENTS:
            raise WiresharkError(f"tshark rejected the arguments: {stderr.strip()}")
        if returncode != 0:
            # The distinction is whether anything was read. A failure with
            # nothing yielded means tshark never got started on the file -
            # missing, unreadable, not a capture - and must be an error:
            # swallowing it would let the pipeline record "0 events" as a
            # successful parse, which reads as "the capture was empty".
            # A failure *after* packets were read is a truncated capture (a
            # killed tcpdump, a partial download), which is common enough
            # in real DFIR work that it must not discard what was read.
            if yielded == 0:
                raise WiresharkError(
                    f"tshark exited {returncode} without reading any packets: {stderr.strip()}"
                )
            logger.warning(
                f"tshark exited {returncode} after {yielded:,} packets from '{pcap_path}'; "
                f"keeping the packets already read. {stderr.strip()}"
            )
