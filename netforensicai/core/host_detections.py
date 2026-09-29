"""Bundled offline host rules over Windows events (Security/System/PowerShell
EVTX via parsers/windows_events.py, and Sysmon).

Same contract as core/detections.py, which drives these from its single
streaming pass in scan_case:
  - host_rules_for_event(event) yields (rule_id, rule_name, severity,
    description) for one event;
  - _HostAggregateState.feed()/results() covers what only shows across many
    events (brute force, spraying, Kerberoasting), yielding
    (rule_id, rule_name, severity, description, representative_event).

Each rule names its MITRE ATT&CK technique in the description, and like
every rule in this tool it says "may indicate", never "is": most of these
behaviours have a legitimate administrator doing them somewhere. What they
share is that each is specific enough to be worth a look on its own - a
generic "a service was installed" rule is deliberately absent, because a
Windows machine installs drivers weekly and a rule that fires on all of them
teaches people to ignore it.
"""

import ipaddress
import ntpath
import re

# --- tunables ---

# Failed logons against ONE account before it reads as guessing rather than
# a mistyped password. Lockout policies commonly trip at 5-10; attackers
# pace below that, so this is set at the low end.
BRUTE_FORCE_MIN_FAILURES = 10
# Distinct accounts failed from ONE source before it reads as spraying.
SPRAY_MIN_ACCOUNTS = 5
# Distinct services one requester got RC4 tickets for before Kerberoasting
# is rated high rather than medium.
KERBEROAST_HIGH_SERVICES = 3

_SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
           "rundll32.exe", "regsvr32.exe", "bitsadmin.exe", "certutil.exe"}
_OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe",
           "mspub.exe", "visio.exe"}

_PRIVILEGED_GROUPS = {
    "administrators", "domain admins", "enterprise admins", "schema admins",
    "account operators", "backup operators", "server operators", "dnsadmins",
    "group policy creator owners", "remote desktop users",
}

# (process basename, compiled pattern on the lowercased command line,
#  rule_id, severity, what it does, ATT&CK technique).
# Patterns are the specific abuse, not the binary: certutil verifying a
# certificate is fine, certutil -urlcache pulling a file is not.
_LOLBIN_ABUSE = (
    ("certutil.exe", re.compile(r"-urlcache|-verifyctl|/urlcache"), "LOLBIN-DOWNLOAD", "high",
     "certutil used to download a file", "T1105"),
    ("certutil.exe", re.compile(r"[-/]decode(hex)?\b"), "LOLBIN-DECODE", "medium",
     "certutil used to decode a file (common for staging encoded payloads)", "T1140"),
    ("bitsadmin.exe", re.compile(r"/transfer|/addfile"), "LOLBIN-DOWNLOAD", "high",
     "bitsadmin used to transfer a file", "T1197"),
    ("mshta.exe", re.compile(r"https?://|javascript:|vbscript:"), "LOLBIN-EXECUTION", "high",
     "mshta executing remote or inline script", "T1218.005"),
    ("regsvr32.exe", re.compile(r"/i:\s*https?://|scrobj\.dll"), "LOLBIN-EXECUTION", "high",
     "regsvr32 loading a remote scriptlet (Squiblydoo)", "T1218.010"),
    ("rundll32.exe", re.compile(r"comsvcs(\.dll)?\s*,?\s*#?(minidump|24)"), "LSASS-DUMP", "high",
     "rundll32 comsvcs.dll MiniDump - the standard living-off-the-land LSASS memory dump", "T1003.001"),
    ("rundll32.exe", re.compile(r"javascript:|https?://"), "LOLBIN-EXECUTION", "high",
     "rundll32 executing script or a remote resource", "T1218.011"),
    ("wmic.exe", re.compile(r"process\s+call\s+create"), "LOLBIN-EXECUTION", "medium",
     "wmic spawning a process (remote if /node: is present)", "T1047"),
    ("vssadmin.exe", re.compile(r"delete\s+shadows|resize\s+shadowstorage"), "INHIBIT-RECOVERY", "high",
     "volume shadow copies deleted", "T1490"),
    ("wmic.exe", re.compile(r"shadowcopy\s+delete"), "INHIBIT-RECOVERY", "high",
     "volume shadow copies deleted via wmic", "T1490"),
    ("wbadmin.exe", re.compile(r"delete\s+(catalog|systemstatebackup)"), "INHIBIT-RECOVERY", "high",
     "Windows backup catalog deleted", "T1490"),
    ("bcdedit.exe", re.compile(r"recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures"),
     "INHIBIT-RECOVERY", "high", "Windows recovery disabled via bcdedit", "T1490"),
    ("procdump.exe", re.compile(r"lsass"), "LSASS-DUMP", "high",
     "procdump targeting LSASS", "T1003.001"),
    ("reg.exe", re.compile(r"save\s+hklm\\(sam|security|system)\b"), "CREDENTIAL-HIVE-EXPORT", "high",
     "registry hive holding credentials exported", "T1003.002"),
    ("ntdsutil.exe", re.compile(r"ifm|snapshot"), "CREDENTIAL-HIVE-EXPORT", "high",
     "ntdsutil creating an NTDS.dit copy", "T1003.003"),
)

_RULE_NAMES = {
    "LOLBIN-DOWNLOAD": "Built-in Windows tool used to download a file",
    "LOLBIN-DECODE": "Built-in Windows tool used to decode a file",
    "LOLBIN-EXECUTION": "Built-in Windows tool used to proxy code execution",
    "LSASS-DUMP": "LSASS process memory dumped",
    "INHIBIT-RECOVERY": "System recovery inhibited",
    "CREDENTIAL-HIVE-EXPORT": "Credential store exported",
}

_ENCODED_PS = re.compile(r"\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedc\w*)\s+[a-z0-9+/=]{20,}", re.IGNORECASE)

# Content of a PowerShell script block (or command line) that is specific
# to offensive use. Each is (pattern, what it is, ATT&CK technique).
_SUSPICIOUS_PS_CONTENT = (
    (re.compile(r"amsiutils|amsiinitfailed|amsiscanbuffer", re.I), "an AMSI bypass", "T1562.001"),
    (re.compile(r"(downloadstring|downloaddata|downloadfile)\s*\(", re.I), "a download cradle", "T1105"),
    (re.compile(r"\b(iex|invoke-expression)\b.{0,80}\b(net\.webclient|invoke-webrequest|iwr|irm|invoke-restmethod)\b|"
                r"\b(net\.webclient|invoke-webrequest|iwr|irm|invoke-restmethod)\b.{0,200}\|\s*(iex|invoke-expression)\b", re.I | re.S),
     "download-and-execute", "T1059.001"),
    (re.compile(r"invoke-mimikatz|sekurlsa::|lsadump::|kerberos::golden", re.I), "Mimikatz", "T1003"),
    (re.compile(r"invoke-kerberoast|invoke-bloodhound|sharphound|invoke-shellcode|invoke-reflectivepeinjection|"
                r"powerup|invoke-allchecks|get-gpppassword", re.I), "a known offensive PowerShell module", "T1059.001"),
    (re.compile(r"virtualalloc.{0,200}(createthread|memset)|\[system\.runtime\.interopservices\.marshal\]::copy", re.I | re.S),
     "in-memory shellcode loading", "T1055"),
)

# Service or scheduled-task command lines that point at execution from a
# user-writable location or via an interpreter - how PsExec-style lateral
# movement and most persistence look, and not how vendor software installs.
_SUSPICIOUS_LAUNCH = re.compile(
    r"psexesvc|%comspec%|\bcmd(\.exe)?\s+/[ck]\b|powershell|pwsh|mshta|rundll32|regsvr32|wscript|cscript|"
    r"\\(temp|tmp|appdata|programdata|users\\public|perflogs)\\|\\\\127\.0\.0\.1\\|\\\\localhost\\|"
    r"frombase64string|-enc\b",
    re.IGNORECASE,
)


def _is_external(address):
    """Routable on the internet. Not detections._is_private's inverse on
    purpose: that module imports this one, and an unparseable value must
    not read as external here."""
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return False


def _basename(path):
    return ntpath.basename(path or "").lower()


def _account_key(user):
    """'CORP\\Bob', 'bob@corp.local' and 'bob' -> 'bob'.

    Different event IDs name the same account differently (4625 carries a
    domain, 4771 does not), and the aggregate rules must see them as one.
    """
    name = (user or "").strip().lower()
    name = name.rsplit("\\", 1)[-1]
    return name.split("@", 1)[0]


def _data(event):
    return (event.raw_event_reference or {}).get("event_data") or {}


def host_rules_for_event(event):
    event_type = event.event_type

    if event_type in ("audit_log_cleared", "event_log_cleared"):
        yield (
            "LOG-CLEARED",
            "Windows event log cleared",
            "high",
            f"{event.message or 'An event log was cleared'}. Clearing logs destroys the record of what "
            f"happened before it and is a common anti-forensics step (ATT&CK T1070.001). Anything earlier "
            f"on this host may be missing from this evidence.",
        )

    elif event_type == "process_start":
        yield from _process_rules(event)

    elif event_type == "powershell_script_block" and event.command_line:
        for pattern, what, technique in _SUSPICIOUS_PS_CONTENT:
            if pattern.search(event.command_line):
                yield (
                    "SUSPICIOUS-POWERSHELL",
                    "PowerShell script block with offensive content",
                    "high",
                    f"A logged PowerShell script block contains {what} (ATT&CK {technique}). Script-block "
                    f"logging records the de-obfuscated code, so this is what actually ran.",
                )
                break

    elif event_type == "service_installed":
        launch = event.command_line or event.file_path or ""
        if _SUSPICIOUS_LAUNCH.search(launch):
            yield (
                "SUSPICIOUS-SERVICE",
                "Service installed with a suspicious command",
                "high",
                f"{event.message or 'A service was installed'}. The service command runs an interpreter or "
                f"a binary from a user-writable location - how PsExec-style remote execution and service "
                f"persistence look (ATT&CK T1543.003 / T1569.002).",
            )

    elif event_type in ("scheduled_task_created", "scheduled_task_updated"):
        content = _data(event).get("TaskContent") or ""
        match = _SUSPICIOUS_LAUNCH.search(content)
        if match:
            yield (
                "SUSPICIOUS-SCHEDULED-TASK",
                "Scheduled task runs a suspicious command",
                "medium",
                f"{event.message or 'A scheduled task was created'}. Its action references "
                f"'{match.group(0)}' - scheduled tasks are a common persistence mechanism "
                f"(ATT&CK T1053.005).",
            )

    elif event_type == "group_member_added":
        group = (_data(event).get("TargetUserName") or "").strip()
        if group.lower() in _PRIVILEGED_GROUPS:
            severity = "medium" if group.lower() == "remote desktop users" else "high"
            yield (
                "PRIVILEGED-GROUP-CHANGE",
                "Account added to a privileged group",
                severity,
                f"{event.message}. Membership of '{group}' grants elevated or remote access; adding an "
                f"account is how attackers keep the access they gained (ATT&CK T1098).",
            )

    elif event_type == "logon_success":
        data = _data(event)
        logon_type = (data.get("LogonType") or "").strip()
        if logon_type == "10" and event.src_ip and _is_external(event.src_ip):
            yield (
                "EXTERNAL-RDP-LOGON",
                "RDP logon from an external address",
                "high",
                f"{event.message}. Remote Desktop exposed to and used from the internet is one of the most "
                f"common initial-access routes (ATT&CK T1133 / T1021.001).",
            )
        if logon_type == "9" and (data.get("LogonProcessName") or "").strip().lower() == "seclogo":
            yield (
                "NEW-CREDENTIALS-LOGON",
                "Logon with alternate credentials for network use",
                "medium",
                f"{event.message}. Logon type 9 via seclogo is what 'runas /netonly' produces - and also "
                f"what pass-the-hash tooling produces (ATT&CK T1550.002). Check the process that "
                f"requested it.",
            )


def _process_rules(event):
    image = _basename(event.process_name)
    parent = _basename(event.parent_process)
    command = (event.command_line or "").lower()

    if parent in _OFFICE and image in _SHELLS:
        yield (
            "OFFICE-SPAWNED-SHELL",
            "Office application started a shell or script host",
            "high",
            f"{parent} started {image}. Documents do not normally launch interpreters; this is the "
            f"classic sign of a malicious macro or exploit (ATT&CK T1204.002 / T1566.001).",
        )

    if image in ("powershell.exe", "pwsh.exe") and _ENCODED_PS.search(f" {command} "):
        yield (
            "ENCODED-POWERSHELL",
            "PowerShell run with an encoded command",
            "medium",
            "PowerShell was started with -EncodedCommand, which hides the script from the command line "
            "(ATT&CK T1027 / T1059.001). Decode the argument (Base64, UTF-16LE) to see what ran.",
        )

    for name, pattern, rule_id, severity, what, technique in _LOLBIN_ABUSE:
        if image == name and pattern.search(command):
            yield (
                rule_id,
                _RULE_NAMES[rule_id],
                severity,
                f"{what} (ATT&CK {technique}): {_clip(event.command_line)}",
            )
            break


def _clip(text, limit=160):
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


class _HostAggregateState:
    """Brute force, password spraying, and Kerberoasting - rules that only
    exist across many events. Relies on scan_case feeding events in
    timestamp order (CaseStore.iter_events orders by timestamp), which is
    what makes "a success AFTER the failures" meaningful.
    """

    def __init__(self):
        self.failures_by_account = {}  # account -> [count, sources, first_event]
        self.failures_by_source = {}   # src_ip -> [accounts, first_event]
        self.success_after = {}        # ("account"|"source", key) -> first success event after threshold
        self.rc4_tickets = {}          # (requester account, src_ip) -> [services, first_event]

    def feed(self, event):
        event_type = event.event_type
        if event_type in ("logon_failure", "kerberos_preauth_failure"):
            self._feed_failure(event)
        elif event_type == "logon_success":
            self._feed_success(event)
        elif event_type == "kerberos_service_ticket":
            self._feed_ticket(event)

    def _feed_failure(self, event):
        account = _account_key(event.user)
        if account:
            entry = self.failures_by_account.setdefault(account, [0, set(), event])
            entry[0] += 1
            if event.src_ip:
                entry[1].add(event.src_ip)
        if event.src_ip and account:
            entry = self.failures_by_source.setdefault(event.src_ip, [set(), event])
            entry[0].add(account)

    def _feed_success(self, event):
        # Machine accounts (NAME$) and service logons authenticate constantly
        # and are not what a guessed password logs in as.
        account = _account_key(event.user)
        if not account or account.endswith("$") or (_data(event).get("LogonType") or "").strip() == "5":
            return
        failures = self.failures_by_account.get(account)
        if failures and failures[0] >= BRUTE_FORCE_MIN_FAILURES:
            self.success_after.setdefault(("account", account), event)
        sprayed = self.failures_by_source.get(event.src_ip) if event.src_ip else None
        if sprayed and len(sprayed[0]) >= SPRAY_MIN_ACCOUNTS:
            self.success_after.setdefault(("source", event.src_ip), event)

    def _feed_ticket(self, event):
        data = _data(event)
        enc = (data.get("TicketEncryptionType") or "").strip().lower()
        service = (data.get("ServiceName") or "").strip()
        status = (data.get("Status") or "0x0").strip().lower()
        # RC4 tickets for machine accounts and krbtgt are routine; for a
        # user-run service account they are what Kerberoasting requests.
        if enc not in ("0x17", "0x18") or status != "0x0" or not service:
            return
        if service.endswith("$") or service.lower() == "krbtgt":
            return
        entry = self.rc4_tickets.setdefault((_account_key(event.user), event.src_ip), [set(), event])
        entry[0].add(service)

    def results(self):
        for account, (count, sources, first) in sorted(self.failures_by_account.items()):
            if count < BRUTE_FORCE_MIN_FAILURES:
                continue
            origin = f" from {', '.join(sorted(sources)[:5])}" if sources else ""
            success = self.success_after.get(("account", account))
            if success is not None:
                yield (
                    "BRUTE-FORCE-SUCCESS",
                    "Successful logon after repeated failures",
                    "high",
                    f"{count} failed logons for '{first.user}'{origin}, then a successful one "
                    f"({success.message}). A guessed password may have worked - treat the account as "
                    f"compromised until shown otherwise (ATT&CK T1110.001).",
                    success,
                )
            else:
                yield (
                    "BRUTE-FORCE",
                    "Repeated failed logons for one account",
                    "medium",
                    f"{count} failed logons for '{first.user}'{origin} with no later success in this "
                    f"evidence (ATT&CK T1110.001).",
                    first,
                )

        for src_ip, (accounts, first) in sorted(self.failures_by_source.items()):
            if len(accounts) < SPRAY_MIN_ACCOUNTS:
                continue
            success = self.success_after.get(("source", src_ip))
            yield (
                "PASSWORD-SPRAY",
                "One source failing logons across many accounts",
                "high" if success is not None else "medium",
                f"{src_ip} failed to log on as {len(accounts)} different accounts - the pattern of trying "
                f"one password against many users (ATT&CK T1110.003)."
                + (f" A logon from this source then succeeded: {success.message}." if success is not None else ""),
                success or first,
            )

        for (requester, src_ip), (services, first) in sorted(
            self.rc4_tickets.items(), key=lambda item: (item[0][0], item[0][1] or "")
        ):
            listed = ", ".join(sorted(services)[:5]) + (" …" if len(services) > 5 else "")
            yield (
                "KERBEROASTING",
                "RC4 service tickets requested for service accounts",
                "high" if len(services) >= KERBEROAST_HIGH_SERVICES else "medium",
                f"'{first.user or requester}'" + (f" from {src_ip}" if src_ip else "")
                + f" requested RC4-encrypted service tickets for {len(services)} service(s): {listed}. RC4 "
                f"tickets can be cracked offline to recover the service account's password (ATT&CK "
                f"T1558.003).",
                first,
            )
