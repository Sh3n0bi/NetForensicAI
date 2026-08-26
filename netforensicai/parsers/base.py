"""Parser plugin interface.

Every evidence-format parser (pcap now, JSON/CSV next, EVTX/Sysmon later)
implements BaseParser and registers itself under the Evidence.evidence_type
value(s) it handles, so the ingestion pipeline can dispatch by evidence
type without knowing about individual formats or being rewritten when a
new one is added.
"""

from abc import ABC, abstractmethod

_REGISTRY = {}


class BaseParser(ABC):
    #: Evidence.evidence_type values this parser can handle, e.g. ("pcap",)
    evidence_types = ()

    @abstractmethod
    def parse(self, file_path, evidence_id, **options):
        """Parse file_path (the stored evidence copy) into a list of Event objects.

        **options are format-specific parse-time knobs (e.g. the pcap parser's
        output_dir for saving extracted files). The registered parser instance
        itself stays stateless/config-free so one instance can serve every
        call regardless of per-invocation options.
        """
        raise NotImplementedError


def register(parser):
    """Register a BaseParser instance for each of its evidence_types. Returns the parser."""
    for evidence_type in parser.evidence_types:
        _REGISTRY[evidence_type] = parser
    return parser


def get_parser(evidence_type):
    """Return the registered parser instance for evidence_type, or None if unregistered."""
    return _REGISTRY.get(evidence_type)


def registered_types():
    return tuple(_REGISTRY.keys())
