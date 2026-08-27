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


def test_carved_pcap_filename_with_ip_octets_is_not_a_double_extension(tmp_path):
    # Regression from a real 30 MB capture: the pcap parser names carved
    # files after the TCP stream, so the IP octets' dots made every carved
    # executable look like a disguised double-extension file. The last
    # fragment before ".exe" here is "131_43248", which is not a plausible
    # file extension.
    events = [
        _event(
            "EVT-0001",
            event_type="file_transfer",
            file_name="73.124.22.98_80_to_111.224.250.131_43248.exe",
        )
    ]
    with _seeded_store(tmp_path, events) as store:
        detections = scan_case(store)

    assert [d for d in detections if d["rule_id"] == "DOUBLE-EXTENSION-FILE"] == []


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


def _http_event(event_id, url, user_agent, src_ip="10.0.0.5", dst_ip="203.0.113.7"):
    return _event(
        event_id,
        event_type="http_request",
        src_ip=src_ip,
        dst_ip=dst_ip,
        url=url,
        raw_event_reference={"method": "GET", "host": "target.example", "user_agent": user_agent},
    )


def test_attack_tool_user_agent_is_detected(tmp_path):
    events = [_http_event("EVT-0001", "http://target.example/admin", "gobuster/3.6")]
    with _seeded_store(tmp_path, events) as store:
        detections = scan_case(store)

    assert len(detections) == 1
    assert detections[0]["rule_id"] == "ATTACK-TOOL-USER-AGENT"
    assert detections[0]["severity"] == "high"
    assert "gobuster" in detections[0]["description"]


def test_sqlmap_user_agent_is_detected(tmp_path):
    events = [_http_event("EVT-0001", "http://target.example/p?id=1", "sqlmap/1.8.3#stable (https://sqlmap.org)")]
    with _seeded_store(tmp_path, events) as store:
        detections = scan_case(store)

    assert [d["rule_id"] for d in detections] == ["ATTACK-TOOL-USER-AGENT"]
    assert "sqlmap" in detections[0]["description"]


def test_ordinary_browser_user_agent_is_not_detected(tmp_path):
    events = [
        _http_event("EVT-0001", "http://target.example/", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120")
    ]
    with _seeded_store(tmp_path, events) as store:
        detections = scan_case(store)

    assert detections == []


def test_attack_tool_detections_are_aggregated_not_one_per_request(tmp_path):
    # A real directory brute-force is tens of thousands of requests. One
    # detection per request would bury the finding, so the rule summarizes
    # per (source, tool) and reports the count instead.
    events = [
        _http_event(f"EVT-{i:04d}", f"http://target.example/path-{i}", "gobuster/3.6") for i in range(250)
    ]
    with _seeded_store(tmp_path, events) as store:
        detections = scan_case(store)

    tool_hits = [d for d in detections if d["rule_id"] == "ATTACK-TOOL-USER-AGENT"]
    assert len(tool_hits) == 1
    assert "250 HTTP request(s)" in tool_hits[0]["description"]


def test_http_path_enumeration_is_detected_on_many_distinct_paths(tmp_path):
    events = [
        _http_event(f"EVT-{i:04d}", f"http://target.example/dir-{i}", "curl/8.0") for i in range(150)
    ]
    with _seeded_store(tmp_path, events) as store:
        detections = scan_case(store)

    scan_hits = [d for d in detections if d["rule_id"] == "HTTP-PATH-ENUMERATION"]
    assert len(scan_hits) == 1
    assert "150 distinct URL paths" in scan_hits[0]["description"]


def test_normal_browsing_volume_does_not_trigger_path_enumeration(tmp_path):
    # A heavy page load pulls in tens of assets, not hundreds - that must
    # stay below the threshold or the rule is useless in practice.
    events = [_http_event(f"EVT-{i:04d}", f"http://target.example/asset-{i}", "curl/8.0") for i in range(40)]
    with _seeded_store(tmp_path, events) as store:
        detections = scan_case(store)

    assert [d for d in detections if d["rule_id"] == "HTTP-PATH-ENUMERATION"] == []


def test_repeated_requests_to_same_path_do_not_trigger_enumeration(tmp_path):
    # Volume alone isn't the signal - it's *distinct paths*. Hammering one
    # URL is a different behavior (and shouldn't be reported as discovery).
    events = [_http_event(f"EVT-{i:04d}", "http://target.example/same", "curl/8.0") for i in range(300)]
    with _seeded_store(tmp_path, events) as store:
        detections = scan_case(store)

    assert [d for d in detections if d["rule_id"] == "HTTP-PATH-ENUMERATION"] == []


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
