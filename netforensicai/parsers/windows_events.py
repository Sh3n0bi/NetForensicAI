"""Windows Security / System / PowerShell event log -> Common Event Model.

Sysmon is covered in evtx.py. This module covers the logs most incidents are
actually worked from when Sysmon was never deployed: the Security log
(logons, process creation, account and group changes, Kerberos/NTLM), the
System log (service installs, log clearing) and PowerShell script-block
logging.

Each supported (provider, EventID) maps to a function that turns the record's
named EventData into Event fields plus a one-line human-readable message.
Everything the mapper does not lift into a field stays in
raw_event_reference["event_data"] (evtx.py keeps it for every record), so
nothing is lost - detections that need e.g. LogonType read it from there.

Field conventions, chosen so the entity graph joins across sources:
  - user      - "DOMAIN\\name" when the record gives a domain, else "name".
                The account the event is ABOUT (the one logging on, the one
                created), not necessarily the one that caused it; the actor
                is named in the message when it differs.
  - src_ip    - the remote address of a logon/auth attempt, IPv4-mapped IPv6
                ("::ffff:10.0.0.5") unwrapped so it joins with pcap IPs.
  - hostname  - always the machine that WROTE the log (from <Computer>),
                set by evtx.py - never overwritten here.
Windows writes "-" (and sometimes "" or "NULL SID"-style placeholders) for
"not applicable"; those become None rather than entities named "-".
"""

import ipaddress
import ntpath

SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"
EVENTLOG_PROVIDER = "Microsoft-Windows-Eventlog"
SCM_PROVIDER = "Service Control Manager"
POWERSHELL_PROVIDER = "Microsoft-Windows-PowerShell"

# https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624
LOGON_TYPES = {
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive (RDP)",
    "11": "CachedInteractive",
    "12": "CachedRemoteInteractive",
    "13": "CachedUnlock",
}

# NTSTATUS codes in 4625 Status/SubStatus and 4776 Status. SubStatus is the
# more specific of the two, so it is preferred when present.
FAILURE_REASONS = {
    "0xc0000064": "account does not exist",
    "0xc000006a": "wrong password",
    "0xc000006d": "bad username or password",
    "0xc000006e": "account restriction",
    "0xc000006f": "outside permitted logon hours",
    "0xc0000070": "workstation not permitted",
    "0xc0000071": "password expired",
    "0xc0000072": "account disabled",
    "0xc000015b": "logon type not granted",
    "0xc0000193": "account expired",
    "0xc0000224": "password must change",
    "0xc0000234": "account locked out",
}

# Kerberos pre-authentication failure codes (4771 Status).
KERBEROS_FAILURES = {
    "0x6": "unknown principal",
    "0x12": "account disabled, expired or locked out",
    "0x17": "password expired",
    "0x18": "wrong password",
}

# Kerberos ticket encryption types (4768/4769 TicketEncryptionType). RC4 on a
# service ticket is the classic Kerberoasting tell, so it is named outright.
KERBEROS_ENCRYPTION = {
    "0x1": "DES-CBC-CRC",
    "0x3": "DES-CBC-MD5",
    "0x11": "AES128",
    "0x12": "AES256",
    "0x17": "RC4-HMAC",
    "0x18": "RC4-HMAC-EXP",
}

_PLACEHOLDERS = {"", "-", "null", "n/a"}


def _clean(value):
    if value is None:
        return None
    value = str(value).strip()
    return None if value.lower() in _PLACEHOLDERS else value


def _account(data, domain_key, name_key):
    name = _clean(data.get(name_key))
    if not name:
        return None
    domain = _clean(data.get(domain_key))
    return f"{domain}\\{name}" if domain else name


def _ip(value):
    value = _clean(value)
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


def _port(value):
    try:
        port = int(_clean(value))
    except (TypeError, ValueError):
        return None
    # 0 is "no port" in these records, not a real one.
    return port if 0 < port <= 65535 else None


def _pid(value):
    # Security events write PIDs as hex ("0x1a4"); tolerate decimal too.
    value = _clean(value)
    if not value:
        return None
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except ValueError:
        return None


def _code(value):
    value = _clean(value)
    return value.lower() if value else None


def _logon_type(data):
    raw = _clean(data.get("LogonType"))
    return f"type {raw} ({LOGON_TYPES.get(raw, 'unknown')})" if raw else "unknown type"


def _suffix(*parts):
    """' part1 part2' for the parts that are set, '' otherwise."""
    text = " ".join(p for p in parts if p)
    return f" {text}" if text else ""


def _source(ip, port=None, workstation=None):
    """'from 10.0.0.5:51234 (WS01)' - whichever parts the record carries."""
    if ip:
        where = f"{ip}:{port}" if port else ip
        if workstation and workstation.lower() != ip.lower():
            where += f" ({workstation})"
    elif workstation:
        where = workstation
    else:
        return ""
    return f"from {where}"


# --- mappers: data -> (fields, message) ---


def _logon_success(data):
    user = _account(data, "TargetDomainName", "TargetUserName")
    ip, port = _ip(data.get("IpAddress")), _port(data.get("IpPort"))
    workstation = _clean(data.get("WorkstationName"))
    fields = {"user": user, "src_ip": ip, "src_port": port, "process_name": _clean(data.get("ProcessName"))}
    elevated = " (elevated token)" if _code(data.get("ElevatedToken")) == "%%1842" else ""
    return fields, f"Logon success: {user or 'unknown account'}, {_logon_type(data)}{elevated}" + _suffix(
        _source(ip, port, workstation)
    )


def _logon_failure(data):
    user = _account(data, "TargetDomainName", "TargetUserName")
    ip, port = _ip(data.get("IpAddress")), _port(data.get("IpPort"))
    workstation = _clean(data.get("WorkstationName"))
    code = _code(data.get("SubStatus"))
    if not code or code == "0x0":
        code = _code(data.get("Status"))
    reason = FAILURE_REASONS.get(code, code or "unknown reason")
    fields = {"user": user, "src_ip": ip, "src_port": port, "process_name": _clean(data.get("ProcessName"))}
    return fields, f"Logon failure: {user or 'unknown account'}, {_logon_type(data)} - {reason}" + _suffix(
        _source(ip, port, workstation)
    )


def _logoff(data):
    user = _account(data, "TargetDomainName", "TargetUserName")
    return {"user": user}, f"Logoff: {user or 'unknown account'}" + (
        f", {_logon_type(data)}" if data.get("LogonType") else ""
    )


def _explicit_credentials(data):
    actor = _account(data, "SubjectDomainName", "SubjectUserName")
    target = _account(data, "TargetDomainName", "TargetUserName")
    server = _clean(data.get("TargetServerName"))
    ip = _ip(data.get("IpAddress"))
    fields = {"user": target, "dst_ip": ip, "process_name": _clean(data.get("ProcessName"))}
    return fields, f"Explicit credentials used: {actor or 'unknown'} ran as {target or 'unknown'}" + _suffix(
        f"against {server}" if server and server.lower() != "localhost" else None
    )


def _special_privileges(data):
    user = _account(data, "SubjectDomainName", "SubjectUserName")
    privileges = " ".join((data.get("PrivilegeList") or "").split())
    return {"user": user}, f"Special privileges assigned to new logon: {user or 'unknown account'}" + (
        f" ({privileges})" if privileges else ""
    )


def _process_created(data):
    user = _account(data, "SubjectDomainName", "SubjectUserName")
    # Newer builds also record the account the process runs as; prefer it
    # when present (it differs from the creator for e.g. runas).
    target = _account(data, "TargetDomainName", "TargetUserName")
    image = _clean(data.get("NewProcessName"))
    fields = {
        "user": target or user,
        "process_name": image,
        "process_id": _pid(data.get("NewProcessId")),
        "parent_process": _clean(data.get("ParentProcessName")),
        "command_line": _clean(data.get("CommandLine")),
    }
    return fields, f"Process created: {ntpath.basename(image) if image else 'unknown'} by {target or user or 'unknown'}"


def _process_exited(data):
    user = _account(data, "SubjectDomainName", "SubjectUserName")
    image = _clean(data.get("ProcessName"))
    fields = {"user": user, "process_name": image, "process_id": _pid(data.get("ProcessId"))}
    return fields, f"Process exited: {ntpath.basename(image) if image else 'unknown'}"


def _service_installed_security(data):
    actor = _account(data, "SubjectDomainName", "SubjectUserName")
    return _service_fields(
        data.get("ServiceName"), data.get("ServiceFileName"), data.get("ServiceAccount"), actor
    )


def _service_installed_system(data):
    return _service_fields(data.get("ServiceName"), data.get("ImagePath"), data.get("AccountName"), None)


def _service_fields(name, image, account, actor):
    name, image, account = _clean(name), _clean(image), _clean(account)
    fields = {"user": actor or account, "file_path": image, "command_line": image}
    message = f"Service installed: {name or 'unnamed'}" + _suffix(
        f"-> {image}" if image else None, f"running as {account}" if account else None
    )
    return fields, message


def _scheduled_task(verb):
    def mapper(data):
        actor = _account(data, "SubjectDomainName", "SubjectUserName")
        task = _clean(data.get("TaskName"))
        return {"user": actor, "file_path": task}, f"Scheduled task {verb}: {task or 'unnamed'} by {actor or 'unknown'}"

    return mapper


def _account_change(verb):
    def mapper(data):
        target = _account(data, "TargetDomainName", "TargetUserName")
        actor = _account(data, "SubjectDomainName", "SubjectUserName")
        return {"user": target}, f"User account {verb}: {target or 'unknown'} by {actor or 'unknown'}"

    return mapper


def _group_member_added(data):
    group = _account(data, "TargetDomainName", "TargetUserName")
    actor = _account(data, "SubjectDomainName", "SubjectUserName")
    # MemberName is an LDAP DN for domain groups and "-" for local groups
    # (which only carry MemberSid); use whichever names the member.
    member = _clean(data.get("MemberName")) or _clean(data.get("MemberSid"))
    return {"user": member}, f"Member added to group {group or 'unknown'}: {member or 'unknown'} by {actor or 'unknown'}"


def _account_locked_out(data):
    # 4740 puts the CALLER machine in TargetDomainName, not a domain.
    target = _clean(data.get("TargetUserName"))
    caller = _clean(data.get("TargetDomainName"))
    return {"user": target}, f"Account locked out: {target or 'unknown'}" + (f" (from {caller})" if caller else "")


def _kerberos_tgt(data):
    user = _account(data, "TargetDomainName", "TargetUserName")
    ip = _ip(data.get("IpAddress"))
    status = _code(data.get("Status"))
    outcome = "granted" if status in (None, "0x0") else f"failed ({KERBEROS_FAILURES.get(status, status)})"
    enc = KERBEROS_ENCRYPTION.get(_code(data.get("TicketEncryptionType")))
    return {"user": user, "src_ip": ip, "src_port": _port(data.get("IpPort"))}, (
        f"Kerberos TGT {outcome}: {user or 'unknown'}" + _suffix(f"[{enc}]" if enc else None, _source(ip))
    )


def _kerberos_service_ticket(data):
    user = _account(data, "TargetDomainName", "TargetUserName")
    service = _clean(data.get("ServiceName"))
    ip = _ip(data.get("IpAddress"))
    enc = KERBEROS_ENCRYPTION.get(_code(data.get("TicketEncryptionType")))
    return {"user": user, "src_ip": ip, "src_port": _port(data.get("IpPort"))}, (
        f"Kerberos service ticket: {user or 'unknown'} -> {service or 'unknown service'}"
        + _suffix(f"[{enc}]" if enc else None, _source(ip))
    )


def _kerberos_preauth_failure(data):
    user = _clean(data.get("TargetUserName"))
    ip = _ip(data.get("IpAddress"))
    status = _code(data.get("Status"))
    reason = KERBEROS_FAILURES.get(status, status or "unknown reason")
    return {"user": user, "src_ip": ip, "src_port": _port(data.get("IpPort"))}, (
        f"Kerberos pre-authentication failed: {user or 'unknown'} - {reason}" + _suffix(_source(ip))
    )


def _ntlm_validation(data):
    user = _clean(data.get("TargetUserName"))
    workstation = _clean(data.get("Workstation"))
    status = _code(data.get("Status"))
    outcome = "succeeded" if status in (None, "0x0") else f"failed ({FAILURE_REASONS.get(status, status)})"
    return {"user": user}, f"NTLM credential validation {outcome}: {user or 'unknown'}" + _suffix(
        _source(None, workstation=workstation)
    )


def _log_cleared(data):
    actor = _account(data, "SubjectDomainName", "SubjectUserName")
    channel = _clean(data.get("Channel")) or "Security"
    return {"user": actor}, f"{channel} event log cleared by {actor or 'unknown account'}"


def _script_block(data):
    text = _clean(data.get("ScriptBlockText"))
    path = _clean(data.get("Path"))
    part = _clean(data.get("MessageNumber"))
    total = _clean(data.get("MessageTotal"))
    fields = {"command_line": text, "file_path": path, "process_name": "powershell.exe"}
    chunk = f" (part {part}/{total})" if total and total != "1" else ""
    preview = " ".join((text or "").split())[:80]
    return fields, f"PowerShell script block{chunk}: {preview or '(empty)'}"


# (provider, EventID) -> (event_type, mapper). event_type names are the
# stable contract detections and filters key on.
WINDOWS_EVENT_MAPPERS = {
    (SECURITY_PROVIDER, "4624"): ("logon_success", _logon_success),
    (SECURITY_PROVIDER, "4625"): ("logon_failure", _logon_failure),
    (SECURITY_PROVIDER, "4634"): ("logoff", _logoff),
    (SECURITY_PROVIDER, "4647"): ("logoff", _logoff),
    (SECURITY_PROVIDER, "4648"): ("explicit_credential_logon", _explicit_credentials),
    (SECURITY_PROVIDER, "4672"): ("special_privileges_logon", _special_privileges),
    (SECURITY_PROVIDER, "4688"): ("process_start", _process_created),
    (SECURITY_PROVIDER, "4689"): ("process_stop", _process_exited),
    (SECURITY_PROVIDER, "4697"): ("service_installed", _service_installed_security),
    (SECURITY_PROVIDER, "4698"): ("scheduled_task_created", _scheduled_task("created")),
    (SECURITY_PROVIDER, "4702"): ("scheduled_task_updated", _scheduled_task("updated")),
    (SECURITY_PROVIDER, "4720"): ("user_account_created", _account_change("created")),
    (SECURITY_PROVIDER, "4722"): ("user_account_enabled", _account_change("enabled")),
    (SECURITY_PROVIDER, "4724"): ("password_reset", _account_change("password reset")),
    (SECURITY_PROVIDER, "4726"): ("user_account_deleted", _account_change("deleted")),
    (SECURITY_PROVIDER, "4728"): ("group_member_added", _group_member_added),
    (SECURITY_PROVIDER, "4732"): ("group_member_added", _group_member_added),
    (SECURITY_PROVIDER, "4756"): ("group_member_added", _group_member_added),
    (SECURITY_PROVIDER, "4740"): ("account_locked_out", _account_locked_out),
    (SECURITY_PROVIDER, "4768"): ("kerberos_tgt_request", _kerberos_tgt),
    (SECURITY_PROVIDER, "4769"): ("kerberos_service_ticket", _kerberos_service_ticket),
    (SECURITY_PROVIDER, "4771"): ("kerberos_preauth_failure", _kerberos_preauth_failure),
    (SECURITY_PROVIDER, "4776"): ("ntlm_authentication", _ntlm_validation),
    (EVENTLOG_PROVIDER, "1102"): ("audit_log_cleared", _log_cleared),
    (EVENTLOG_PROVIDER, "104"): ("event_log_cleared", _log_cleared),
    (SCM_PROVIDER, "7045"): ("service_installed", _service_installed_system),
    (POWERSHELL_PROVIDER, "4104"): ("powershell_script_block", _script_block),
}


def map_windows_event(provider, event_id, data):
    """(event_type, fields, message) for a supported record, else None.

    fields never contains None values, so callers can splat it into Event.
    """
    entry = WINDOWS_EVENT_MAPPERS.get((provider, event_id))
    if entry is None:
        return None
    event_type, mapper = entry
    fields, message = mapper(data)
    return event_type, {k: v for k, v in fields.items() if v is not None}, message
