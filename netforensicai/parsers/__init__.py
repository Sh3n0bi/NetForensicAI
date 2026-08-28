"""Parser plugin package.

Call load_parsers() once before looking a parser up via base.get_parser()
- it imports every known parser module (each one self-registers via
base.register() at import time), skipping any whose optional dependencies
aren't installed. This keeps the base package importable without, say,
the [pcap] extra, while still discovering pcap support when it is there.
"""

import logging

logger = logging.getLogger(__name__)

_KNOWN_PARSER_MODULES = (
    # pcap_engine registers for "pcap" and imports neither dissection
    # engine at module scope, so pcap support is discovered whenever
    # *either* scapy or tshark is present. Listing parsers.pcap here
    # instead would make scapy's absence remove pcap support entirely,
    # even on a machine with Wireshark installed.
    "netforensicai.parsers.pcap_engine",
    "netforensicai.parsers.generic",
    "netforensicai.parsers.evtx",
)

_loaded = False


def load_parsers():
    global _loaded
    if _loaded:
        return
    for module_name in _KNOWN_PARSER_MODULES:
        try:
            __import__(module_name)
        except ImportError as e:
            logger.debug(f"Skipping parser module {module_name}: {e}")
    _loaded = True
