from datetime import datetime, timezone

from netforensicai.core.attack import T1027, T1059, T1059_001, T1105, scan_case
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


def test_powershell_process_maps_to_t1059_001(tmp_path):
    events = [_event("EVT-0001", process_name="powershell.exe", command_line="powershell.exe -Command Get-Process")]
    with _seeded_store(tmp_path, events) as store:
        touched = scan_case(store)

        assert (T1059_001[0], T1059_001[1]) in touched
        techniques = store.list_techniques()
        match = next(t for t in techniques if t["technique_id"] == T1059_001[0])
        assert match["status"] == "potential"
        assert match["event_count"] == 1


def test_encoded_powershell_also_maps_to_t1027(tmp_path):
    events = [
        _event(
            "EVT-0001",
            process_name="powershell.exe",
            command_line="powershell.exe -enc SQBFAFgA",
        )
    ]
    with _seeded_store(tmp_path, events) as store:
        touched = scan_case(store)

    ids = {t[0] for t in touched}
    assert T1059_001[0] in ids
    assert T1027[0] in ids


def test_plain_powershell_without_encoding_does_not_trigger_t1027(tmp_path):
    events = [_event("EVT-0001", process_name="powershell.exe", command_line="powershell.exe -Command Get-Process")]
    with _seeded_store(tmp_path, events) as store:
        touched = scan_case(store)

    ids = {t[0] for t in touched}
    assert T1027[0] not in ids


def test_generic_interpreter_maps_to_t1059_not_t1059_001(tmp_path):
    events = [_event("EVT-0001", process_name="cmd.exe", command_line="cmd.exe /c dir")]
    with _seeded_store(tmp_path, events) as store:
        touched = scan_case(store)

    ids = {t[0] for t in touched}
    assert T1059[0] in ids
    assert T1059_001[0] not in ids


def test_exe_file_transfer_maps_to_t1105(tmp_path):
    events = [_event("EVT-0001", event_type="file_transfer", file_name="payload.exe")]
    with _seeded_store(tmp_path, events) as store:
        touched = scan_case(store)

    assert (T1105[0], T1105[1]) in touched


def test_non_exe_file_transfer_does_not_trigger_t1105(tmp_path):
    events = [_event("EVT-0001", event_type="file_transfer", file_name="document.pdf")]
    with _seeded_store(tmp_path, events) as store:
        touched = scan_case(store)

    assert touched == []


def test_unrelated_events_produce_no_mappings(tmp_path):
    events = [_event("EVT-0001", event_type="authentication", user="jdoe")]
    with _seeded_store(tmp_path, events) as store:
        touched = scan_case(store)

    assert touched == []


def test_rescanning_preserves_investigator_set_status(tmp_path):
    events = [_event("EVT-0001", process_name="powershell.exe")]
    with _seeded_store(tmp_path, events) as store:
        scan_case(store)
        store.update_technique_status(T1059_001[0], "confirmed", datetime.now(timezone.utc))

        scan_case(store)  # rescan should not reset status back to "potential"

        match = store.get_technique(T1059_001[0])
        assert match["status"] == "confirmed"


def test_multiple_events_link_to_same_technique(tmp_path):
    events = [
        _event("EVT-0001", process_name="powershell.exe"),
        _event("EVT-0002", process_name="powershell.exe"),
    ]
    with _seeded_store(tmp_path, events) as store:
        scan_case(store)

        technique_events = store.technique_events(T1059_001[0])
        assert {e["event_id"] for e in technique_events} == {"EVT-0001", "EVT-0002"}
        assert store.list_techniques()[0]["event_count"] == 2


def test_relinking_same_event_twice_does_not_duplicate(tmp_path):
    events = [_event("EVT-0001", process_name="powershell.exe")]
    with _seeded_store(tmp_path, events) as store:
        scan_case(store)
        scan_case(store)

        assert len(store.technique_events(T1059_001[0])) == 1


def test_count_techniques(tmp_path):
    events = [_event("EVT-0001", process_name="powershell.exe"), _event("EVT-0002", event_type="file_transfer", file_name="x.exe")]
    with _seeded_store(tmp_path, events) as store:
        scan_case(store)

        assert store.count_techniques() == 2
