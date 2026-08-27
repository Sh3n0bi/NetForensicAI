from datetime import datetime, timezone

from netforensicai.core.detections import scan_case
from netforensicai.core.event import Event
from netforensicai.core.store import CaseStore


def _event(event_id, **overrides):
    fields = dict(
        event_id=event_id,
        evidence_id="EV-0001",
        source="json",
        event_type="process_start",
        timestamp=datetime(2026, 8, 27, 9, 0, 0, tzinfo=timezone.utc),
    )
    fields.update(overrides)
    return Event(**fields)


def _seeded_store(tmp_path, events):
    store = CaseStore(tmp_path)
    store.replace_events_for_evidence("EV-0001", events)
    return store


def test_known_offensive_tool_name_is_detected(tmp_path):
    events = [_event("EVT-0001", process_name="mimikatz.exe")]
    with _seeded_store(tmp_path, events) as store:
        detections = scan_case(store)

        assert len(detections) == 1
        assert detections[0]["rule_id"] == "OFFENSIVE-TOOL-NAME"
        assert detections[0]["severity"] == "high"
        assert detections[0]["event_id"] == "EVT-0001"
        assert "mimikatz.exe" in detections[0]["description"]


def test_unrelated_process_name_is_not_detected(tmp_path):
    events = [_event("EVT-0001", process_name="explorer.exe")]
    with _seeded_store(tmp_path, events) as store:
        detections = scan_case(store)

    assert detections == []


def test_suspicious_port_is_detected(tmp_path):
    events = [_event("EVT-0001", event_type="network_connection", src_ip="10.0.0.5", dst_ip="10.0.0.9", dst_port=4444)]
    with _seeded_store(tmp_path, events) as store:
        detections = scan_case(store)

    assert len(detections) == 1
    assert detections[0]["rule_id"] == "SUSPICIOUS-PORT"
    assert detections[0]["severity"] == "medium"


def test_ordinary_port_is_not_detected(tmp_path):
    events = [_event("EVT-0001", event_type="network_connection", src_ip="10.0.0.5", dst_ip="10.0.0.9", dst_port=443)]
    with _seeded_store(tmp_path, events) as store:
        detections = scan_case(store)

    assert detections == []


def test_double_extension_file_is_detected(tmp_path):
    events = [_event("EVT-0001", event_type="file_transfer", file_name="invoice.pdf.exe")]
    with _seeded_store(tmp_path, events) as store:
        detections = scan_case(store)

    assert len(detections) == 1
    assert detections[0]["rule_id"] == "DOUBLE-EXTENSION-FILE"
    assert detections[0]["severity"] == "high"


def test_single_extension_executable_is_not_detected(tmp_path):
    # A plain .exe with no disguise attempt isn't the pattern this rule
    # targets - that's just "an executable", not inherently suspicious.
    events = [_event("EVT-0001", event_type="file_transfer", file_name="setup.exe")]
    with _seeded_store(tmp_path, events) as store:
        detections = scan_case(store)

    assert detections == []


def test_non_executable_double_extension_is_not_detected(tmp_path):
    events = [_event("EVT-0001", event_type="file_transfer", file_name="archive.tar.gz")]
    with _seeded_store(tmp_path, events) as store:
        detections = scan_case(store)

    assert detections == []


def test_credential_artifact_path_is_detected(tmp_path):
    events = [
        _event(
            "EVT-0001",
            event_type="file_access",
            file_path="C:\\Windows\\System32\\config\\SAM",
            file_name="SAM",
        )
    ]
    with _seeded_store(tmp_path, events) as store:
        detections = scan_case(store)

    assert len(detections) == 1
    assert detections[0]["rule_id"] == "CREDENTIAL-ARTIFACT"
    assert detections[0]["severity"] == "high"


def test_lsass_dump_filename_is_detected(tmp_path):
    events = [_event("EVT-0001", event_type="file_transfer", file_name="lsass.dmp")]
    with _seeded_store(tmp_path, events) as store:
        detections = scan_case(store)

    assert len(detections) == 1
    assert detections[0]["rule_id"] == "CREDENTIAL-ARTIFACT"


def test_unrelated_events_produce_no_detections(tmp_path):
    events = [_event("EVT-0001", event_type="authentication", user="jdoe")]
    with _seeded_store(tmp_path, events) as store:
        detections = scan_case(store)

    assert detections == []


def test_rescanning_does_not_duplicate(tmp_path):
    events = [_event("EVT-0001", process_name="mimikatz.exe")]
    with _seeded_store(tmp_path, events) as store:
        scan_case(store)
        scan_case(store)

        assert store.count_detections() == 1


def test_rescanning_drops_stale_detections(tmp_path):
    # Detections have no investigator-set status to preserve (unlike
    # ATT&CK mappings) - if the underlying event no longer matches, a
    # rescan should simply stop reporting it.
    events = [_event("EVT-0001", process_name="mimikatz.exe")]
    with _seeded_store(tmp_path, events) as store:
        scan_case(store)
        assert store.count_detections() == 1

        store.replace_events_for_evidence("EV-0001", [_event("EVT-0001", process_name="explorer.exe")])
        scan_case(store)

        assert store.count_detections() == 0


def test_multiple_rules_can_match_the_same_case(tmp_path):
    events = [
        _event("EVT-0001", process_name="mimikatz.exe"),
        _event("EVT-0002", event_type="network_connection", dst_port=4444),
        _event("EVT-0003", event_type="file_transfer", file_name="invoice.pdf.exe"),
    ]
    with _seeded_store(tmp_path, events) as store:
        detections = scan_case(store)

        assert {d["rule_id"] for d in detections} == {"OFFENSIVE-TOOL-NAME", "SUSPICIOUS-PORT", "DOUBLE-EXTENSION-FILE"}
        assert store.count_detections() == 3


def test_list_detections_filters_by_severity(tmp_path):
    events = [
        _event("EVT-0001", process_name="mimikatz.exe"),  # high
        _event("EVT-0002", event_type="network_connection", dst_port=4444),  # medium
    ]
    with _seeded_store(tmp_path, events) as store:
        scan_case(store)

        high_only = store.list_detections(severity="high")
        assert len(high_only) == 1
        assert high_only[0]["rule_id"] == "OFFENSIVE-TOOL-NAME"
