"""Chooses which pcap dissection engine parses a capture, and is the
parser the ingestion pipeline actually gets for evidence_type "pcap".

Two engines exist and neither is a superset of the other:

  scapy   (parsers/pcap.py)         pure Python, no external binary, seven
                                    hand-written analyses
  tshark  (parsers/pcap_tshark.py)  Wireshark's ~3000 dissectors and real
                                    object export, needs Wireshark installed

This module holds the choice between them in ONE place rather than
letting each caller decide, because the choice has to be identical
everywhere - `netforensic parse`, `analyze`, the web upload endpoint and
each live-capture rotation must not disagree about how a case's evidence
was dissected. It also keeps the two engine modules independent: neither
imports the other, so a machine with tshark but no scapy still gets pcap
support, which is not true if the scapy module has to be importable to
reach the registry.

Resolution order for the engine, most specific first:

  1. an explicit engine= passed to parse (the CLI's --engine)
  2. NETFORENSIC_PCAP_ENGINE in the environment
  3. the saved `pcap_engine` setting
  4. "auto"

"auto" prefers tshark when it is installed. The preference is recorded on
every event it produces (raw_event_reference["engine"]) rather than only
being logged, because "which dissector produced this" is a question a
defensible report has to be able to answer months later, on a machine
that may no longer have the same tooling.
"""

import logging
import os

from netforensicai.parsers import base

logger = logging.getLogger(__name__)

ENGINE_AUTO = "auto"
ENGINE_TSHARK = "tshark"
ENGINE_SCAPY = "scapy"
VALID_ENGINES = (ENGINE_AUTO, ENGINE_TSHARK, ENGINE_SCAPY)

ENGINE_ENV = "NETFORENSIC_PCAP_ENGINE"


class EngineUnavailableError(Exception):
    """Raised when a specifically requested engine is not installed.

    Deliberately not a silent fallback: an analyst who passed
    `--engine tshark` is asking for a reproducible dissection, and quietly
    giving them a different one would put results in a report that cannot
    be reproduced by the command that appears next to them.
    """


def configured_engine():
    """The engine preference, before availability is taken into account."""
    from netforensicai.core import config

    value = (os.environ.get(ENGINE_ENV) or config.get_plain("pcap_engine") or ENGINE_AUTO).strip().lower()
    if value not in VALID_ENGINES:
        logger.warning(f"Unknown pcap engine '{value}'; falling back to '{ENGINE_AUTO}'.")
        return ENGINE_AUTO
    return value


def resolve_engine(engine=None):
    """Return the concrete engine name to use: "tshark" or "scapy".

    Raises EngineUnavailableError if a specific engine was demanded and is
    not installed.
    """
    from netforensicai.integrations import wireshark

    requested = (engine or "").strip().lower() or configured_engine()
    if requested not in VALID_ENGINES:
        raise EngineUnavailableError(
            f"Unknown pcap engine '{requested}'. Choose one of: {', '.join(VALID_ENGINES)}."
        )

    if requested == ENGINE_TSHARK:
        if not wireshark.available():
            raise EngineUnavailableError(
                "The tshark engine was requested but tshark was not found. Install Wireshark, "
                "or set NETFORENSIC_TSHARK to its executable."
            )
        return ENGINE_TSHARK

    if requested == ENGINE_SCAPY:
        return ENGINE_SCAPY

    return ENGINE_TSHARK if wireshark.available() else ENGINE_SCAPY


def engine_status(engine=None):
    """What `wireshark status` and the web UI report: which engine would be
    used right now, and why."""
    from netforensicai.integrations import wireshark

    requested = (engine or "").strip().lower() or configured_engine()
    try:
        selected = resolve_engine(engine)
        error = None
    except EngineUnavailableError as e:
        selected = None
        error = str(e)
    return {
        "requested": requested,
        "selected": selected,
        "error": error,
        "tshark_available": wireshark.available(),
        "tshark_version": wireshark.version(),
    }


class PcapEngineParser(base.BaseParser):
    evidence_types = ("pcap",)

    def parse(self, file_path, evidence_id, **options):
        return list(self.iter_parse(file_path, evidence_id, **options))

    def iter_parse(
        self,
        file_path,
        evidence_id,
        output_dir=None,
        engine=None,
        display_filter=None,
        **options,
    ):
        """Delegate to the resolved engine, streaming its events through
        unchanged.

        display_filter is tshark-only: it narrows the parse to matching
        packets, which is how a focused subset of a very large capture is
        ingested without carving a slice first. Asking for one while the
        scapy engine is in use is an error rather than a silent no-op -
        an analyst who filtered and got everything would draw exactly the
        wrong conclusion from the result.
        """
        selected = resolve_engine(engine)

        if selected == ENGINE_TSHARK:
            from netforensicai.parsers import pcap_tshark

            logger.info(f"Dissecting '{file_path}' with the tshark engine.")
            return pcap_tshark.iter_parse(
                file_path,
                evidence_id,
                output_dir=output_dir,
                display_filter=display_filter,
                **_only(options, "anomaly_contamination"),
            )

        if display_filter:
            raise EngineUnavailableError(
                "Display filters need the tshark engine, but it is not in use. Install "
                "Wireshark, or drop the filter to parse the whole capture with scapy."
            )

        from netforensicai.parsers import pcap as pcap_scapy

        logger.info(f"Dissecting '{file_path}' with the scapy engine.")
        return pcap_scapy.PcapParser().iter_parse(
            file_path,
            evidence_id,
            output_dir=output_dir,
            **_only(options, "anomaly_contamination"),
        )


def _only(options, *names):
    """Pass through just the options an engine understands. The pipeline
    hands every parser the same option bag, so an engine must not receive
    - or reject - another format's knobs."""
    return {name: options[name] for name in names if name in options}


base.register(PcapEngineParser())
