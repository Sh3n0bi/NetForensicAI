"""The false-positive audit, as a test.

Every detection rule looks perfect against the incident it was written
for. What decides whether anyone keeps the tool switched on is what it
does on the other 99.9% of traffic - and specifically on the traffic that
RESEMBLES an incident and is not one.

These are the cases that a rule reading only volume, only regularity or
only file extension gets wrong. Each was verified to actually fire before
the corresponding rule was tightened, so none of them is hypothetical.
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
from netforensicai.core import narrative as narrative_module, pipeline  # noqa: E402

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def _module(name):
    spec = importlib.util.spec_from_file_location(name, SAMPLES / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def benign(tmp_path_factory):
    from scapy.all import wrpcap

    _module("generate_incident")  # generate_benign imports from it
    path = tmp_path_factory.mktemp("benign") / "benign.pcap"
    wrpcap(str(path), _module("generate_benign").build(scale=20))
    return path


def _detections(root, capture):
    manager = CaseManager(root)
    case = manager.create(name="Audit", investigator="test")
    case_dir = manager.cases_dir / case.case_id
    evidence = EvidenceManager(case_dir).add(capture, case_id=case.case_id)
    manager.register_evidence(case.case_id, evidence.evidence_id)

    with CaseStore(case_dir) as store:
        _e, _n, error = pipeline.parse_evidence_item(
            evidence, case_dir, manager, case.case_id, store
        )
        assert error is None, error
        return scan_case(store), narrative_module.build(store)


def test_ordinary_browsing_is_not_reported_as_exfiltration(tmp_path, benign):
    """THE REGRESSION THIS FILE EXISTS FOR.

    Request headers, cookies and form posts to one web host add up past
    any absolute threshold low enough to still catch a small
    exfiltration. Measured on this capture, an absolute-volume rule fired
    on 11 ordinary browsing sessions to a CDN, sending 4-9 KB each while
    receiving 36-49 KB back. Direction is what separates a browser from
    an upload.
    """
    detections, _story = _detections(tmp_path, benign)
    cdn_hits = [
        d for d in detections
        if d["rule_id"] == "OUTBOUND-BULK-TRANSFER" and "151.101.1.140" in d["description"]
    ]

    assert cdn_hits == [], f"browsing reported as bulk transfer: {len(cdn_hits)} hit(s)"


def test_the_off_site_backup_is_still_reported(tmp_path, benign):
    """The other half of the same rule. Suppressing browsing must not
    suppress a genuinely outbound-dominant transfer - a rule that never
    fires on legitimate-looking traffic is usually a rule that never
    fires."""
    detections, _story = _detections(tmp_path, benign)
    backup_hits = [
        d for d in detections
        if d["rule_id"] == "OUTBOUND-BULK-TRANSFER" and "52.94.236.248" in d["description"]
    ]

    assert backup_hits, "a genuinely outbound-dominant transfer should still be reported"


def test_an_internal_monitoring_agent_is_not_reported_as_a_beacon(tmp_path, benign):
    """Machine-regular by design, every 60 seconds, forever. What makes a
    beacon a finding is that it leaves the network - an agent talking to
    its own server does not."""
    detections, _story = _detections(tmp_path, benign)
    beacons = [d for d in detections if d["rule_id"] == "PERIODIC-BEACON"]

    assert beacons == [], f"internal heartbeat reported as a beacon: {beacons}"


def test_an_installer_downloaded_over_tls_is_not_reported(tmp_path, benign):
    """What makes a download a finding is the cleartext, not the file
    type."""
    detections, _story = _detections(tmp_path, benign)

    assert [d for d in detections if d["rule_id"] == "EXECUTABLE-DOWNLOAD"] == []


def test_a_login_over_tls_is_not_reported_as_a_cleartext_credential(tmp_path, benign):
    """The credential in this capture is real and completely invisible,
    which is the correct outcome: the rule fires on the absence of
    encryption, not on the presence of a login."""
    detections, _story = _detections(tmp_path, benign)

    assert [d for d in detections if d["rule_id"] == "CLEARTEXT-CREDENTIALS"] == []
    assert [d for d in detections if d["rule_id"] == "CREDENTIAL-REUSE"] == []


def test_an_internal_file_copy_is_not_reported(tmp_path, benign):
    detections, _story = _detections(tmp_path, benign)
    internal = [
        d for d in detections
        if d["rule_id"] == "OUTBOUND-BULK-TRANSFER" and "10.20.30.9" in d["description"]
    ]

    assert internal == []


def test_the_narrative_does_not_overstate_a_benign_capture(tmp_path, benign):
    """A day of normal traffic must not come back as an intrusion. The
    assessment escalates on the STAGES present, so a capture with only a
    transfer finding cannot reach the language reserved for one that also
    shows a credential going out."""
    _detections_, story = _detections(tmp_path, benign)

    assert story.severity in ("none", "low", "high")
    assert "credential" not in story.assessment.lower()
    phases = {key for key, _title, _beats in story.phases}
    assert "credential-access" not in phases
    assert "command-and-control" not in phases
