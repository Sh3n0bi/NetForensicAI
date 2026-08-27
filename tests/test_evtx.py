"""Tests for the EVTX/Sysmon parser.

record_to_event() is tested with hand-crafted XML matching the real
Windows Event Log / Sysmon schema (public, well-documented format - not
proprietary or personal data), verified against real python-evtx output
during development. The file-reading layer (_load_records /
EvtxParser.parse) is tested against a mocked Evtx.Evtx, since committing
a real .evtx binary fixture either requires real machine data (a privacy
concern for a public repo) or an elevated-privilege Sysmon/Event Log
setup this test suite shouldn't depend on. The binary parsing itself is
python-evtx's responsibility, not this module's.
"""

from unittest.mock import MagicMock, patch

import pytest

from netforensicai.parsers.evtx import (
    EvtxParseError,
    EvtxParser,
    _extract_sha256,
    _load_records,
    record_to_event,
)


# Real EVTX System-section shape, generic (non-Sysmon) provider - matches
# actual python-evtx .xml() output verified against a real exported
# Windows System-log record during development.
GENERIC_EVENT_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="EventLog"></Provider>
<EventID Qualifiers="32768">6013</EventID>
<Version>0</Version>
<Level>4</Level>
<TimeCreated SystemTime="2026-06-09 07:00:00.056051+00:00"></TimeCreated>
<EventRecordID>103188</EventRecordID>
<Channel>System</Channel>
<Computer>WORKSTATION01</Computer>
</System>
<EventData><Data>&lt;string&gt;186101&lt;/string&gt;
</Data>
</EventData>
</Event>"""


def _sysmon_xml(event_id, data_pairs, computer="WORKSTATION01"):
    data_xml = "".join(f'<Data Name="{name}">{value}</Data>' for name, value in data_pairs)
    return f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-Sysmon" Guid="{{5770385f-c22a-43e0-bf4c-06f5698ffbd9}}"></Provider>
<EventID>{event_id}</EventID>
<TimeCreated SystemTime="2026-08-27T09:00:00.1234567Z"></TimeCreated>
<EventRecordID>12345</EventRecordID>
<Channel>Microsoft-Windows-Sysmon/Operational</Channel>
<Computer>{computer}</Computer>
</System>
<EventData>{data_xml}</EventData>
</Event>"""


def test_generic_windows_event_uses_system_fields_only():
    event = record_to_event(GENERIC_EVENT_XML, evidence_id="EV-0001", sequence=_seq())

    assert event.event_type == "windows_event:EventLog"
    assert event.hostname == "WORKSTATION01"
    assert event.timestamp is not None
    assert event.raw_event_reference["windows_event_id"] == "6013"
    assert event.raw_event_reference["record_id"] == "103188"
    assert event.raw_event_reference["channel"] == "System"


def test_sysmon_process_create_maps_rich_fields():
    xml = _sysmon_xml(
        1,
        [
            ("Image", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            ("CommandLine", "powershell.exe -enc AAAA"),
            ("User", r"WORKSTATION01\jdoe"),
            ("ParentImage", r"C:\Windows\explorer.exe"),
            ("Hashes", "SHA1=DEADBEEF,SHA256=CAFEF00D1234,IMPHASH=ABCDEF"),
        ],
    )

    event = record_to_event(xml, evidence_id="EV-0001", sequence=_seq())

    assert event.event_type == "process_start"
    assert event.process_name == r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    assert event.command_line == "powershell.exe -enc AAAA"
    assert event.user == r"WORKSTATION01\jdoe"
    assert event.parent_process == r"C:\Windows\explorer.exe"
    assert event.file_hash == "CAFEF00D1234"
    assert event.hostname == "WORKSTATION01"
    assert event.source == "evtx"


def test_sysmon_network_connection_maps_network_fields():
    xml = _sysmon_xml(
        3,
        [
            ("SourceIp", "192.168.1.10"),
            ("SourcePort", "51000"),
            ("DestinationIp", "203.0.113.7"),
            ("DestinationPort", "4444"),
            ("Protocol", "tcp"),
            ("Image", r"C:\evil.exe"),
        ],
    )

    event = record_to_event(xml, evidence_id="EV-0001", sequence=_seq())

    assert event.event_type == "network_connection"
    assert event.src_ip == "192.168.1.10"
    assert event.src_port == 51000
    assert event.dst_ip == "203.0.113.7"
    assert event.dst_port == 4444
    assert event.protocol == "tcp"


def test_sysmon_file_create_derives_file_name_from_path():
    xml = _sysmon_xml(11, [("TargetFilename", r"C:\Users\jdoe\Downloads\payload.exe"), ("Image", r"C:\evil.exe")])

    event = record_to_event(xml, evidence_id="EV-0001", sequence=_seq())

    assert event.event_type == "file_created"
    assert event.file_path == r"C:\Users\jdoe\Downloads\payload.exe"
    assert event.file_name == "payload.exe"


def test_sysmon_dns_query_maps_domain():
    xml = _sysmon_xml(22, [("QueryName", "malicious.example.com"), ("Image", r"C:\evil.exe")])

    event = record_to_event(xml, evidence_id="EV-0001", sequence=_seq())

    assert event.event_type == "dns_query"
    assert event.domain == "malicious.example.com"


def test_unrecognized_sysmon_event_id_falls_back_to_generic():
    xml = _sysmon_xml(999, [("SomeField", "value")])

    event = record_to_event(xml, evidence_id="EV-0001", sequence=_seq())

    assert event.event_type == "windows_event:Microsoft-Windows-Sysmon"


def test_malformed_xml_returns_none_not_raise():
    result = record_to_event("<Event><System><Broken", evidence_id="EV-0001", sequence=_seq())

    assert result is None


def test_extract_sha256_from_composite_hashes():
    assert _extract_sha256("SHA1=DEAD,SHA256=CAFEF00D,IMPHASH=ABCD") == "CAFEF00D"


def test_extract_sha256_falls_back_to_raw_when_no_sha256():
    assert _extract_sha256("MD5=DEADBEEF") == "MD5=DEADBEEF"


def test_load_records_wraps_missing_file_error():
    with pytest.raises(EvtxParseError):
        list(_load_records("does/not/exist.evtx"))


def test_parser_reads_records_via_mocked_evtx_library(tmp_path):
    fake_path = tmp_path / "sample.evtx"
    fake_path.write_bytes(b"not a real evtx - the library is mocked")

    mock_record_1 = MagicMock()
    mock_record_1.xml.return_value = GENERIC_EVENT_XML
    mock_record_2 = MagicMock()
    mock_record_2.xml.return_value = _sysmon_xml(1, [("Image", r"C:\evil.exe")])

    mock_log = MagicMock()
    mock_log.records.return_value = [mock_record_1, mock_record_2]
    mock_log.__enter__.return_value = mock_log
    mock_log.__exit__.return_value = False

    with patch("Evtx.Evtx.Evtx", return_value=mock_log):
        events = EvtxParser().parse(fake_path, evidence_id="EV-0001")

    assert len(events) == 2
    assert {e.event_type for e in events} == {"windows_event:EventLog", "process_start"}
    assert all(e.evidence_id == "EV-0001" for e in events)
    assert len(events) == len({e.event_id for e in events})


def test_parser_is_registered_in_base_registry():
    from netforensicai.parsers import base

    assert isinstance(base.get_parser("evtx"), EvtxParser)


def _seq():
    from netforensicai.core.event import EventSequence

    return EventSequence()
