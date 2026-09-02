"""Tests for the demo capture in samples/.

A sample that has quietly stopped producing the incident it claims to is
worse than none: it is the first thing a new reader runs, and the first
thing anybody demos. These pin the story, not the byte layout.

The generator is also the only capture in the repository built to be
DISSECTED rather than merely parsed, which is where the interesting
failure lives - see the sequence-number test.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

pytest.importorskip("scapy")

from netforensicai.core.case import CaseManager  # noqa: E402
from netforensicai.core.detections import scan_case  # noqa: E402
from netforensicai.core.evidence import EvidenceManager  # noqa: E402
from netforensicai.core.store import CaseStore  # noqa: E402
from netforensicai.core import narrative as narrative_module  # noqa: E402
from netforensicai.integrations import wireshark  # noqa: E402
from netforensicai.core import pipeline  # noqa: E402

SAMPLES = Path(__file__).resolve().parent.parent / "samples"

requires_tshark = pytest.mark.skipif(
    not wireshark.available(), reason="Wireshark/tshark is not installed on this machine"
)


@pytest.fixture(autouse=True)
def _use_the_real_engine(monkeypatch):
    """The suite pins dissection to scapy (see conftest) so results do not
    depend on whether Wireshark happens to be installed. This module is
    the exception: the sample exists to demonstrate the path a user
    actually takes, and two of its acts - the cleartext credential and the
    password reused on FTP - are only visible to the tshark engine, which
    is the only one that emits credential_exposure events.
    """
    from netforensicai.parsers import pcap_engine

    monkeypatch.delenv(pcap_engine.ENGINE_ENV, raising=False)


def _generator():
    spec = importlib.util.spec_from_file_location("generate_incident", SAMPLES / "generate_incident.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["generate_incident"] = module
    spec.loader.exec_module(module)
    return module


def _ingest(root, capture):
    """Ingest one capture into a fresh case; return the case directory.

    Goes through the real pipeline rather than calling the parser
    directly, because the sample is meant to prove the path a user
    actually takes.
    """
    manager = CaseManager(root)
    case = manager.create(name="Sample", investigator="test")
    case_dir = manager.cases_dir / case.case_id
    evidence = EvidenceManager(case_dir).add(capture, case_id=case.case_id)
    manager.register_evidence(case.case_id, evidence.evidence_id)

    with CaseStore(case_dir) as store:
        _events, _entities, error = pipeline.parse_evidence_item(
            evidence, case_dir, manager, case.case_id, store
        )
    assert error is None, error
    return case_dir


@pytest.fixture(scope="module")
def capture(tmp_path_factory):
    from scapy.all import wrpcap

    path = tmp_path_factory.mktemp("samples") / "incident.pcap"
    wrpcap(str(path), _generator().build())
    return path


def test_the_capture_is_reproducible(tmp_path):
    """A fixed clock, so two runs are byte-identical. A sample that
    changes every run cannot be diffed and cannot be cited."""
    from scapy.all import wrpcap

    gen = _generator()
    first, second = tmp_path / "a.pcap", tmp_path / "b.pcap"
    wrpcap(str(first), gen.build())
    wrpcap(str(second), gen.build())

    assert first.read_bytes() == second.read_bytes()


def test_no_packet_looks_like_a_retransmission(capture):
    """The failure this guards against is silent and badly misleading.

    With scapy's default seq=0 on every packet, tshark reads the second
    packet in a direction as a retransmission of the first and does not
    hand its payload to the subdissector. An FTP login then dissects as
    raw TCP, the PASS line is never seen, and a working credential rule
    reports nothing - which looks exactly like a bug in the tool.
    """
    if not wireshark.available():
        pytest.skip("needs tshark")

    import subprocess

    result = subprocess.run(
        [wireshark.tshark_path(), "-r", str(capture), "-Y", "tcp.analysis.retransmission",
         "-T", "fields", "-e", "frame.number"],
        capture_output=True, text=True, timeout=120,
    )
    assert result.stdout.strip() == "", f"frames flagged as retransmissions: {result.stdout.split()}"


@requires_tshark
def test_the_sample_tells_the_story_it_claims_to(tmp_path, capture):
    """One test over the whole pipeline, because the sample's value is
    the end-to-end result and not any single stage of it."""
    with CaseStore(_ingest(tmp_path, capture)) as store:
        scan_case(store)
        story = narrative_module.build(store)

    rules = {beat.rule_id for beat in story.beats}
    # Each act of the incident, and the rule that is supposed to see it.
    assert "SUSPICIOUS-TLD" in rules, "act 2: the lookup"
    assert "EXECUTABLE-DOWNLOAD" in rules, "act 3: the download"
    assert "CLEARTEXT-CREDENTIALS" in rules, "act 4: the credential"
    assert "KEY-MATERIAL-IN-TRANSIT" in rules, "act 5: the private key"
    assert "CREDENTIAL-REUSE" in rules, "act 6: the same password on FTP"
    assert "OUTBOUND-BULK-TRANSFER" in rules, "act 6: the upload"
    assert "PERIODIC-BEACON" in rules, "act 7: the beacons"

    assert story.severity == "critical"
    assert "leaving this network" in story.assessment


@requires_tshark
def test_the_upload_is_not_also_called_a_beacon(tmp_path, capture):
    """The chunked upload is regular by nature and would satisfy a naive
    beacon rule. Two findings for one activity sends an analyst chasing
    two leads to the same place."""
    with CaseStore(_ingest(tmp_path, capture)) as store:
        detections = scan_case(store)

    beacons = [d for d in detections if d["rule_id"] == "PERIODIC-BEACON"]
    # The beacons go to the stager; the upload goes to the drop host.
    assert beacons, "the real beacons should still be found"
    for beacon in beacons:
        assert "104.21.7.19" not in beacon["description"], "the FTP upload was misread as a beacon"


@requires_tshark
def test_the_benign_traffic_produces_no_findings(tmp_path):
    """A capture made entirely of findings does not test a detection
    rule, it only confirms it fires. The first act exists to be quiet."""
    from scapy.all import wrpcap

    gen = _generator()
    clock = gen.Clock()
    packets = gen.dns(clock, "www.example.com", gen.BENIGN)
    flow = gen.Flow(clock, gen.VICTIM, gen.BENIGN, 49500, 80)
    flow.c2s(b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n")
    flow.s2c(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
    path = tmp_path / "quiet.pcap"
    wrpcap(str(path), packets + flow.packets)

    with CaseStore(_ingest(tmp_path / "cases", path)) as store:
        detections = scan_case(store)
        story = narrative_module.build(store)

    assert detections == []
    assert story.severity == "none"
    assert "not the same as" in story.assessment
