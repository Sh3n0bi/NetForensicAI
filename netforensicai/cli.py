"""NetForensicAI CLI entrypoint.

`scan` is the pre-case-management pcap workflow carried over from the
original netforensicai.py script. Case/evidence/timeline/investigate
subcommands land in later steps of the DFIR-platform migration.
"""

import logging
import sys
from pathlib import Path
from typing import List

import typer

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

DEFAULT_CASES_DIR = "cases"

# Mirrors core.search / core.streams. Duplicated as literals because a
# Typer option default is evaluated at import time, and importing those
# modules here would make every `netforensic --help` pay for them.
SEARCH_DEFAULT_MAX_HITS = 200
STREAM_DEFAULT_MAX_BYTES = 64 * 1024
CTF_DEFAULT_MAX_HITS = 50
CHAT_DEFAULT_MAX_STEPS = 8

app = typer.Typer(
    name="netforensic",
    help="NetForensicAI - local-first DFIR investigation platform.",
    no_args_is_help=True,
)

case_app = typer.Typer(help="Manage investigation cases.", no_args_is_help=True)
app.add_typer(case_app, name="case")


@case_app.command("create")
def case_create(
    name: str = typer.Option(..., "--name", help="Case name"),
    description: str = typer.Option("", "--description", help="Case description"),
    investigator: str = typer.Option(
        None, "--investigator", help="Investigator name (defaults to the OS username)"
    ),
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
):
    """Create a new case."""
    import getpass

    from netforensicai.core.case import CaseError, CaseManager

    manager = CaseManager(cases_dir)
    try:
        case = manager.create(
            name=name,
            description=description,
            investigator=investigator or getpass.getuser(),
        )
    except CaseError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"Created case {case.case_id}: {case.name}")
    typer.echo(f"  Investigator: {case.investigator}")
    typer.echo(f"  Location:     {Path(cases_dir) / case.case_id}")


@case_app.command("list")
def case_list_cmd(
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
):
    """List all cases."""
    from netforensicai.core.case import CaseManager

    manager = CaseManager(cases_dir)
    cases = manager.list()
    if not cases:
        typer.echo(f"No cases found in {cases_dir}/")
        return

    header = f"{'CASE ID':<10} {'STATUS':<14} {'INVESTIGATOR':<16} {'CREATED':<20} NAME"
    typer.echo(header)
    typer.echo("-" * len(header))
    for case in cases:
        created = case.created_at.split("T")[0]
        typer.echo(f"{case.case_id:<10} {case.status:<14} {case.investigator:<16} {created:<20} {case.name}")


@case_app.command("export")
def case_export_cmd(
    case_id: str = typer.Option(..., "--case", help="Case ID to export"),
    output: str = typer.Option(
        None, "--output", help="Output archive path (defaults to <CASE-ID>.zip in the current directory)"
    ),
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
):
    """Export a case (evidence, DuckDB store, findings, everything under
    cases/<ID>/) to a single portable zip archive, for backup or handing
    off to another investigator. A manifest of every file's SHA-256 is
    recorded in the archive so `case import` can detect tampering or
    corruption before writing anything."""
    from netforensicai.core.case import CaseError, CaseManager
    from netforensicai.core.export import ExportError, export_case

    case_manager = CaseManager(cases_dir)
    try:
        case = case_manager.load(case_id)
    except CaseError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    output_path = Path(output) if output else Path(f"{case.case_id}.zip")
    try:
        export_case(Path(cases_dir) / case.case_id, output_path)
    except ExportError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"Exported {case.case_id} to {output_path}")


@case_app.command("import")
def case_import_cmd(
    archive: str = typer.Argument(..., help="Path to a .zip archive produced by `case export`"),
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory to import the case into",
    ),
):
    """Import a case archive produced by `case export`. Every file in
    the archive is verified against its recorded manifest hash before
    anything is written to disk - a tampered or corrupted archive is
    rejected outright. Keeps the case's original ID; refuses to import
    over an existing case with the same ID."""
    from netforensicai.core.export import ExportError, import_case

    try:
        case_id = import_case(archive, cases_dir)
    except ExportError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"Imported {case_id} into {Path(cases_dir) / case_id}")


@case_app.command("audit")
def case_audit_cmd(
    case_id: str = typer.Option(..., "--case", help="Case ID to show the chain of custody for"),
    verify: bool = typer.Option(
        False, "--verify", help="Only check the hash chain and report whether it is intact"
    ),
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
):
    """Show the case's chain of custody: every action taken on it, by whom
    and when, in order.

    Entries are hash-chained, so `--verify` reports whether the record has
    been altered since it was written. That detects accidental corruption
    and casual after-the-fact editing - not an attacker who controls the
    machine, who could recompute the whole chain.
    """
    from netforensicai.core import audit
    from netforensicai.core.case import CaseError, CaseManager

    case_manager = CaseManager(cases_dir)
    try:
        case = case_manager.load(case_id)
    except CaseError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    case_dir = Path(cases_dir) / case.case_id
    ok, problems = audit.verify(case_dir)

    if verify:
        if ok:
            entries = audit.read_entries(case_dir)
            typer.echo(f"Chain of custody intact: {len(entries)} entr(ies) verified for {case.case_id}.")
            return
        typer.echo(f"CHAIN OF CUSTODY BROKEN for {case.case_id}:", err=True)
        for problem in problems:
            typer.echo(f"  - {problem}", err=True)
        raise typer.Exit(code=1)

    entries = audit.read_entries(case_dir)
    if not entries:
        typer.echo(f"No chain-of-custody entries recorded for {case.case_id}.")
        return

    header = f"{'#':<5} {'TIMESTAMP (UTC)':<21} {'ACTOR':<14} {'ACTION':<26} DETAILS"
    typer.echo(header)
    typer.echo("-" * len(header))
    for entry in entries:
        details = ", ".join(f"{k}={v}" for k, v in (entry.get("details") or {}).items())
        # Trim sub-second precision and the +00:00 suffix for the table: the
        # full value stays in audit.log, and the header says these are UTC.
        timestamp = entry.get("timestamp", "")[:19].replace("T", " ")
        typer.echo(
            f"{entry.get('sequence', '?'):<5} {timestamp:<21} "
            f"{entry.get('actor', ''):<14} {entry.get('action', ''):<26} {details[:80]}"
        )

    typer.echo("")
    if ok:
        typer.echo(f"Chain of custody intact ({len(entries)} entries verified).")
    else:
        typer.echo("WARNING - chain of custody is BROKEN:", err=True)
        for problem in problems:
            typer.echo(f"  - {problem}", err=True)


evidence_app = typer.Typer(help="Manage evidence within a case.", no_args_is_help=True)
app.add_typer(evidence_app, name="evidence")


@evidence_app.command("add")
def evidence_add(
    file_path: str = typer.Argument(..., help="Path to the evidence file to ingest"),
    case_id: str = typer.Option(..., "--case", help="Case ID to add evidence to (e.g. INC-0001)"),
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
):
    """Ingest a file as evidence: hash it, copy it read-only into the case, and record provenance."""
    from netforensicai.core.case import CaseError, CaseManager
    from netforensicai.core.evidence import EvidenceError, EvidenceManager

    case_manager = CaseManager(cases_dir)
    try:
        case = case_manager.load(case_id)
    except CaseError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    evidence_manager = EvidenceManager(Path(cases_dir) / case.case_id)
    try:
        evidence = evidence_manager.add(file_path, case_id=case.case_id)
    except EvidenceError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    case_manager.register_evidence(case.case_id, evidence.evidence_id)

    typer.echo(f"Ingested {evidence.evidence_id}: {evidence.filename}")
    typer.echo(f"  Type:      {evidence.evidence_type}")
    typer.echo(f"  SHA256:    {evidence.sha256}")
    typer.echo(f"  Size:      {evidence.size_bytes} bytes")
    typer.echo(f"  Imported:  {evidence.imported_at}")
    typer.echo(f"  Source:    {evidence.source_path}")


@evidence_app.command("list")
def evidence_list_cmd(
    case_id: str = typer.Option(..., "--case", help="Case ID to list evidence for"),
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
):
    """List evidence recorded for a case."""
    from netforensicai.core.case import CaseError, CaseManager
    from netforensicai.core.evidence import EvidenceManager

    case_manager = CaseManager(cases_dir)
    try:
        case = case_manager.load(case_id)
    except CaseError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    evidence_manager = EvidenceManager(Path(cases_dir) / case.case_id)
    items = evidence_manager.list()
    if not items:
        typer.echo(f"No evidence recorded for {case.case_id}.")
        return

    header = f"{'EVIDENCE ID':<12} {'TYPE':<8} {'SIZE':>12} {'IMPORTED':<20} FILENAME"
    typer.echo(header)
    typer.echo("-" * len(header))
    for evidence in items:
        imported = evidence.imported_at.split("T")[0]
        typer.echo(
            f"{evidence.evidence_id:<12} {evidence.evidence_type:<8} "
            f"{evidence.size_bytes:>12} {imported:<20} {evidence.filename}"
        )


def _parse_one_evidence(evidence, case_dir, case_manager, case_id, store, parse_options=None):
    """Thin wrapper kept for callers already importing this name; the real
    logic lives in core/pipeline.py so cli.py, the web UI, and the live
    capture module all share exactly one implementation."""
    from netforensicai.core.pipeline import parse_evidence_item

    return parse_evidence_item(evidence, case_dir, case_manager, case_id, store, parse_options)


ENGINE_HELP = (
    "pcap dissection engine: 'auto' (tshark when Wireshark is installed, else scapy), "
    "'tshark', or 'scapy'"
)


@app.command("parse")
def parse_evidence(
    case_id: str = typer.Option(..., "--case", help="Case ID the evidence belongs to"),
    evidence_id: str = typer.Option(..., "--evidence", help="Evidence ID to parse (e.g. EV-0001)"),
    engine: str = typer.Option(None, "--engine", help=ENGINE_HELP),
    display_filter: str = typer.Option(
        None,
        "--display-filter",
        help=(
            "Wireshark display filter restricting which packets are parsed, "
            "e.g. 'ip.addr == 10.0.0.5 && tcp.port == 445'. Needs the tshark engine."
        ),
    ),
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
):
    """Parse one evidence item into normalized events and extract entities."""
    from netforensicai.core.case import CaseError, CaseManager
    from netforensicai.core.evidence import EvidenceError, EvidenceManager
    from netforensicai.core.store import CaseStore

    case_manager = CaseManager(cases_dir)
    try:
        case = case_manager.load(case_id)
    except CaseError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    case_dir = Path(cases_dir) / case.case_id
    try:
        evidence = EvidenceManager(case_dir).load(evidence_id)
    except EvidenceError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    parse_options = {"engine": engine, "display_filter": display_filter}
    with CaseStore(case_dir) as store:
        event_count, entity_count, error = _parse_one_evidence(
            evidence, case_dir, case_manager, case.case_id, store, parse_options
        )

    if error:
        typer.echo(f"Error parsing {evidence_id}: {error}", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"Parsed {evidence_id}: {event_count} events, {entity_count} entities")


@app.command("analyze")
def analyze_case(
    case_id: str = typer.Option(..., "--case", help="Case ID to analyze"),
    engine: str = typer.Option(None, "--engine", help=ENGINE_HELP),
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
):
    """Parse every evidence item in a case that has a registered parser, and extract entities."""
    from netforensicai.core.case import CaseError, CaseManager
    from netforensicai.core.evidence import EvidenceManager
    from netforensicai.core.store import CaseStore

    case_manager = CaseManager(cases_dir)
    try:
        case = case_manager.load(case_id)
    except CaseError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    case_dir = Path(cases_dir) / case.case_id
    items = EvidenceManager(case_dir).list()
    if not items:
        typer.echo(f"No evidence recorded for {case.case_id}. Add some with `netforensic evidence add`.")
        return

    from netforensicai.core.correlation import POSSIBLE_RELATIONSHIP, RELATED, correlate_case
    from netforensicai.core.detections import scan_case as scan_detections

    total_events = 0
    with CaseStore(case_dir) as store:
        for evidence in items:
            event_count, entity_count, error = _parse_one_evidence(
                evidence, case_dir, case_manager, case.case_id, store, {"engine": engine}
            )
            if error:
                typer.echo(f"  {evidence.evidence_id} ({evidence.evidence_type}): skipped - {error}")
                continue
            typer.echo(f"  {evidence.evidence_id} ({evidence.evidence_type}): {event_count} events, {entity_count} entities")
            total_events += event_count

        # Correlation is case-wide (crosses evidence boundaries), so it
        # always runs as a full rebuild over everything now in the store,
        # not just what was parsed in this invocation.
        links = correlate_case(store)
        related_count = sum(1 for link in links if link["relationship_type"] == RELATED)
        possible_count = sum(1 for link in links if link["relationship_type"] == POSSIBLE_RELATIONSHIP)

        # Bundled detection rules: local, deterministic, zero-cost pattern
        # matches - unlike ATT&CK mapping (opt-in, `attack scan`) these run
        # automatically as part of the same pipeline correlation does.
        detections = scan_detections(store)

        # store.count_entities() (the true distinct count) rather than a
        # sum of each evidence item's per-call entity_count: an entity
        # shared across evidence items (exactly what correlation is meant
        # to surface) would otherwise get counted once per evidence item
        # it appears in, inflating the case-wide total.
        total_entities = store.count_entities()

    typer.echo(f"Analysis complete for {case.case_id}: {total_events} events, {total_entities} distinct entities")
    typer.echo(f"Correlation: {related_count} related, {possible_count} possible_relationship (time-proximity only)")
    if detections:
        by_severity = {}
        for d in detections:
            by_severity[d["severity"]] = by_severity.get(d["severity"], 0) + 1
        severity_summary = ", ".join(f"{by_severity[s]} {s}" for s in ("high", "medium", "low") if s in by_severity)
        typer.echo(f"Detections: {len(detections)} rule match(es) ({severity_summary}) - see `netforensic detections list --case {case.case_id}`")
    else:
        typer.echo("Detections: none.")


timeline_app = typer.Typer(help="Build and view the case timeline.", no_args_is_help=True)
app.add_typer(timeline_app, name="timeline")


@timeline_app.command("build")
def timeline_build(
    case_id: str = typer.Option(..., "--case", help="Case ID to build the timeline for"),
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
):
    """Write a point-in-time timeline snapshot to cases/<ID>/timeline/timeline.json."""
    from netforensicai.core.case import CaseError, CaseManager
    from netforensicai.core.store import CaseStore
    from netforensicai.core.timeline import build_timeline, save_timeline

    case_manager = CaseManager(cases_dir)
    try:
        case = case_manager.load(case_id)
    except CaseError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    case_dir = Path(cases_dir) / case.case_id
    with CaseStore(case_dir) as store:
        entries = build_timeline(store)

    output_path = save_timeline(entries, case_dir)
    typer.echo(f"Built timeline for {case.case_id}: {len(entries)} entries -> {output_path}")


def _summarize_entry(entry):
    if entry.message:
        return entry.message[:80]
    parts = []
    for label, value in (
        ("user", entry.user),
        ("hostname", entry.hostname),
        ("src_ip", entry.src_ip),
        ("dst_ip", entry.dst_ip),
        ("process", entry.process_name),
        ("file", entry.file_name),
    ):
        if value:
            parts.append(f"{label}={value}")
    return " ".join(parts) if parts else "(no details)"


@timeline_app.command("show")
def timeline_show(
    case_id: str = typer.Option(..., "--case", help="Case ID to show the timeline for"),
    time_from: str = typer.Option(
        None, "--from", help="Only show entries at or after this time (ISO 8601 or epoch)"
    ),
    time_to: str = typer.Option(
        None, "--to", help="Only show entries at or before this time (ISO 8601 or epoch)"
    ),
    user: str = typer.Option(None, "--user", help="Filter by user"),
    ip: str = typer.Option(None, "--ip", help="Filter by source or destination IP"),
    hostname: str = typer.Option(None, "--hostname", help="Filter by hostname"),
    process: str = typer.Option(None, "--process", help="Filter by process name"),
    file: str = typer.Option(None, "--file", help="Filter by file name or path"),
    event_type: str = typer.Option(None, "--type", help="Filter by event type"),
    evidence_id: str = typer.Option(None, "--evidence", help="Filter by evidence ID"),
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
):
    """Show the case timeline (always queried live from the store), optionally filtered."""
    from netforensicai.core.case import CaseError, CaseManager
    from netforensicai.core.event import parse_timestamp
    from netforensicai.core.store import CaseStore
    from netforensicai.core.timeline import build_timeline, filter_timeline

    case_manager = CaseManager(cases_dir)
    try:
        case = case_manager.load(case_id)
    except CaseError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    parsed_from = parse_timestamp(time_from) if time_from else None
    if time_from and parsed_from is None:
        typer.echo(f"Error: could not parse --from value '{time_from}'", err=True)
        raise typer.Exit(code=1)
    parsed_to = parse_timestamp(time_to) if time_to else None
    if time_to and parsed_to is None:
        typer.echo(f"Error: could not parse --to value '{time_to}'", err=True)
        raise typer.Exit(code=1)

    case_dir = Path(cases_dir) / case.case_id
    with CaseStore(case_dir) as store:
        entries = build_timeline(store)

    entries = filter_timeline(
        entries,
        time_from=parsed_from,
        time_to=parsed_to,
        user=user,
        ip=ip,
        hostname=hostname,
        process=process,
        file=file,
        event_type=event_type,
        evidence_id=evidence_id,
    )

    if not entries:
        typer.echo("No timeline entries match the given filters.")
        return

    header = f"{'TIMESTAMP':<26} {'TYPE':<20} {'SOURCE':<8} {'EVIDENCE':<10} SUMMARY"
    typer.echo(header)
    typer.echo("-" * len(header))
    for entry in entries:
        ts = entry.timestamp.isoformat() if entry.timestamp else "unknown"
        typer.echo(f"{ts:<26} {entry.event_type:<20} {entry.source:<8} {entry.evidence_id:<10} {_summarize_entry(entry)}")


@app.command("investigate")
def investigate(
    case_id: str = typer.Option(..., "--case", help="Case ID to investigate within"),
    ip: str = typer.Option(None, "--ip", help="Investigate an IP address"),
    user: str = typer.Option(None, "--user", help="Investigate a username"),
    hash_value: str = typer.Option(None, "--hash", help="Investigate a file hash"),
    host: str = typer.Option(None, "--host", help="Investigate a hostname"),
    domain: str = typer.Option(None, "--domain", help="Investigate a domain"),
    process: str = typer.Option(None, "--process", help="Investigate a process name"),
    file: str = typer.Option(None, "--file", help="Investigate a file name"),
    device: str = typer.Option(None, "--device", help="Investigate a device"),
    vt_api: str = typer.Option(
        None, "--vt-api", help="VirusTotal API key (falls back to VT_API_KEY env var)"
    ),
    ai: bool = typer.Option(
        False, "--ai", help="Ask the optional AI assistant for one hedged hypothesis about this entity's events"
    ),
    ai_provider: str = typer.Option(
        "anthropic",
        "--ai-provider",
        help="AI provider for --ai: anthropic, openai, ollama, or gemini",
    ),
    api_key: str = typer.Option(
        None,
        "--api-key",
        help="API key for --ai (falls back to the provider's usual env var: ANTHROPIC_API_KEY / "
        "OPENAI_API_KEY / GEMINI_API_KEY; not needed for ollama)",
    ),
    ai_model: str = typer.Option(
        None, "--model", help="Model name override for --ai (defaults to a sane per-provider default)"
    ),
    ollama_url: str = typer.Option(
        None, "--ollama-url", help="Ollama server URL for --ai-provider ollama (default http://localhost:11434)"
    ),
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
):
    """Investigate a single entity: everything this case knows about it, traced back to evidence."""
    from netforensicai.core.case import CaseError, CaseManager
    from netforensicai.core.investigate import investigate_entity
    from netforensicai.core.store import CaseStore

    candidates = {
        "ip_address": ip,
        "user": user,
        "hash": hash_value,
        "hostname": host,
        "domain": domain,
        "process": process,
        "file": file,
        "device": device,
    }
    given = {entity_type: value for entity_type, value in candidates.items() if value}
    if len(given) != 1:
        typer.echo(
            "Error: provide exactly one of --ip, --user, --hash, --host, --domain, --process, --file, --device",
            err=True,
        )
        raise typer.Exit(code=1)
    entity_type, value = next(iter(given.items()))

    case_manager = CaseManager(cases_dir)
    try:
        case = case_manager.load(case_id)
    except CaseError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    case_dir = Path(cases_dir) / case.case_id
    with CaseStore(case_dir) as store:
        result = investigate_entity(store, entity_type, value)

        if result is None:
            typer.echo(f"No evidence of {entity_type} '{value}' found in {case.case_id}.")
            return

        typer.echo(f"Entity: {entity_type} '{value}' ({result.entity['entity_id']})")
        timestamps = [e.timestamp for e in result.events if e.timestamp is not None]
        if timestamps:
            typer.echo(f"  First seen: {min(timestamps).isoformat()}")
            typer.echo(f"  Last seen:  {max(timestamps).isoformat()}")
        typer.echo(f"  Events:     {len(result.events)}")

        typer.echo("\nRelated Evidence:")
        for evidence_id in result.evidence_ids:
            typer.echo(f"  {evidence_id}")

        typer.echo("\nTimeline:")
        for entry in result.timeline_entries:
            ts = entry.timestamp.isoformat() if entry.timestamp else "unknown"
            typer.echo(f"  {ts}  {entry.event_type:<20} {_summarize_entry(entry)}")

        typer.echo("\nRelated Entities:")
        if result.related_entities:
            for rel in result.related_entities[:20]:
                typer.echo(
                    f"  {rel['entity_type']:<16} {rel['value']:<30} ({rel['shared_event_count']} shared events)"
                )
        else:
            typer.echo("  (none)")

        typer.echo("\nPotential Investigation Leads:")
        for lead in result.leads:
            typer.echo(f"  - {lead}")

        typer.echo("\nThreat Intelligence:")
        from netforensicai.core import threat_intel
        from netforensicai.intel import virustotal

        if entity_type in threat_intel.supported_entity_types():
            vt_key = virustotal.get_api_key(vt_api)
            ti_result = threat_intel.check_entity(store, result.entity["entity_id"], entity_type, value, vt_key)
            if ti_result["error"] == "no API key":
                typer.echo("  VirusTotal: not checked (no API key - use --vt-api or set VT_API_KEY)")
            elif ti_result["error"]:
                typer.echo(f"  VirusTotal: error - {ti_result['error']}")
            else:
                status = "FLAGGED MALICIOUS" if ti_result["malicious"] else "not flagged malicious"
                engines = f"{ti_result['malicious_count']}/{ti_result['total_engines']} engines"
                cached_note = " (cached)" if ti_result["cached"] else ""
                typer.echo(f"  VirusTotal: {status} ({engines}){cached_note}")
        else:
            typer.echo("  (no threat intelligence source available for this entity type yet)")

        if ai:
            typer.echo("\nAI Investigation Hypothesis (optional - requires investigator review):")
            from netforensicai.core.ai_assistant import AssistantError, generate_hypothesis

            from netforensicai.core import audit

            # An AI hypothesis sends case events to a third party and may
            # shape what the investigator looks at next, so both the request
            # and its outcome belong in the custody record - including the
            # failures, which show an attempt was made.
            def _record_ai(outcome, **extra):
                audit.record(
                    case_dir,
                    audit.AI_HYPOTHESIS_REQUESTED,
                    {
                        "provider": ai_provider,
                        "model": ai_model or "(provider default)",
                        "entity_type": entity_type,
                        "value": value,
                        "events_sent": len(result.events),
                        "outcome": outcome,
                        **extra,
                    },
                )

            try:
                hypothesis = generate_hypothesis(
                    result.events, provider=ai_provider, api_key=api_key, model=ai_model, base_url=ollama_url
                )
            except AssistantError as e:
                _record_ai("failed", error=str(e))
                typer.echo(f"  Not available: {e}")
            else:
                _record_ai(
                    "returned",
                    evidence_sufficient=hypothesis.evidence_sufficient,
                    confidence=hypothesis.confidence,
                    cited_events=[c.event_id for c in hypothesis.evidence],
                )
                if not hypothesis.evidence_sufficient:
                    typer.echo(f"  {hypothesis.claim}")
                    typer.echo(f"  Recommended validation: {hypothesis.recommended_validation}")
                else:
                    typer.echo(f"  Assessment:  {hypothesis.assessment}")
                    typer.echo(f"  Claim:       {hypothesis.claim}")
                    typer.echo(f"  Confidence:  {hypothesis.confidence}")
                    typer.echo("  Observed evidence:")
                    for line in hypothesis.observed_evidence:
                        typer.echo(f"    - {line}")
                    typer.echo(f"  Alternative explanation: {hypothesis.alternative_explanation}")
                    typer.echo(f"  Recommended validation:  {hypothesis.recommended_validation}")
                    typer.echo("  Cited evidence:")
                    for citation in hypothesis.evidence:
                        typer.echo(f"    - {citation.evidence_id} / {citation.event_id}")
                    typer.echo(
                        "  This is an AI-generated hypothesis, not a conclusion - review the cited "
                        "events yourself. Use `netforensic finding create` if you decide to act on it."
                    )


finding_app = typer.Typer(help="Manage investigator-owned findings.", no_args_is_help=True)
app.add_typer(finding_app, name="finding")


@finding_app.command("create")
def finding_create(
    case_id: str = typer.Option(..., "--case", help="Case ID this finding belongs to"),
    title: str = typer.Option(..., "--title", help="Finding title"),
    severity: str = typer.Option("Medium", "--severity", help="Low, Medium, High, or Critical"),
    status: str = typer.Option("Open", "--status", help="Open, Investigating, Confirmed, Rejected, False Positive, or Resolved"),
    assessment: str = typer.Option("", "--assessment", help="Free-text assessment"),
    event_ids: List[str] = typer.Option(
        [], "--event", help="Event ID this finding is based on, e.g. EVT-EV-0001-000003 (repeatable)"
    ),
    investigator: str = typer.Option(
        None, "--investigator", help="Investigator name (defaults to the OS username)"
    ),
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
):
    """Create an investigator-owned finding. Only the investigator confirms
    what counts as a finding - this command never infers or auto-generates one."""
    import getpass

    from netforensicai.core.case import CaseError, CaseManager
    from netforensicai.core.finding import FindingError, FindingManager
    from netforensicai.core.store import CaseStore

    case_manager = CaseManager(cases_dir)
    try:
        case = case_manager.load(case_id)
    except CaseError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    case_dir = Path(cases_dir) / case.case_id
    evidence_refs = []
    if event_ids:
        with CaseStore(case_dir) as store:
            for event_id in event_ids:
                event = store.get_event(event_id)
                if event is None:
                    typer.echo(f"Error: event_id '{event_id}' not found in {case.case_id}.", err=True)
                    raise typer.Exit(code=1)
                evidence_refs.append({"evidence_id": event.evidence_id, "event_id": event.event_id})

    finding_manager = FindingManager(case_dir)
    try:
        finding = finding_manager.create(
            case_id=case.case_id,
            title=title,
            created_by=investigator or getpass.getuser(),
            severity=severity,
            status=status,
            assessment=assessment,
            evidence_refs=evidence_refs,
        )
    except FindingError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    case_manager.register_finding(case.case_id, finding.finding_id)

    typer.echo(f"Created finding {finding.finding_id}: {finding.title}")
    typer.echo(f"  Status:   {finding.status}")
    typer.echo(f"  Severity: {finding.severity}")
    if finding.evidence_refs:
        typer.echo(f"  Evidence: {', '.join(r['event_id'] for r in finding.evidence_refs)}")


@finding_app.command("list")
def finding_list_cmd(
    case_id: str = typer.Option(..., "--case", help="Case ID to list findings for"),
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
):
    """List findings recorded for a case."""
    from netforensicai.core.case import CaseError, CaseManager
    from netforensicai.core.finding import FindingManager

    case_manager = CaseManager(cases_dir)
    try:
        case = case_manager.load(case_id)
    except CaseError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    findings = FindingManager(Path(cases_dir) / case.case_id).list()
    if not findings:
        typer.echo(f"No findings recorded for {case.case_id}.")
        return

    header = f"{'FINDING ID':<12} {'STATUS':<14} {'SEVERITY':<10} TITLE"
    typer.echo(header)
    typer.echo("-" * len(header))
    for finding in findings:
        typer.echo(f"{finding.finding_id:<12} {finding.status:<14} {finding.severity:<10} {finding.title}")


@finding_app.command("update")
def finding_update(
    case_id: str = typer.Option(..., "--case", help="Case ID the finding belongs to"),
    finding_id: str = typer.Option(..., "--finding", help="Finding ID to update, e.g. F-0001"),
    status: str = typer.Option(None, "--status", help="New status"),
    note: str = typer.Option(None, "--note", help="Append an investigator note"),
    investigator: str = typer.Option(
        None, "--investigator", help="Note author (defaults to the OS username)"
    ),
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
):
    """Update a finding's status and/or append an investigator note."""
    import getpass

    from netforensicai.core.case import CaseError, CaseManager
    from netforensicai.core.finding import FindingError, FindingManager

    if not status and not note:
        typer.echo("Error: provide --status and/or --note", err=True)
        raise typer.Exit(code=1)

    case_manager = CaseManager(cases_dir)
    try:
        case = case_manager.load(case_id)
    except CaseError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    finding_manager = FindingManager(Path(cases_dir) / case.case_id)
    try:
        finding = None
        if status:
            finding = finding_manager.update_status(finding_id, status)
        if note:
            finding = finding_manager.add_note(finding_id, note, investigator or getpass.getuser())
    except FindingError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"Updated {finding.finding_id}: status={finding.status}, notes={len(finding.investigator_notes)}")


attack_app = typer.Typer(
    help="MITRE ATT&CK technique mapping (deterministic, evidence-cited suggestions).", no_args_is_help=True
)
app.add_typer(attack_app, name="attack")


@attack_app.command("scan")
def attack_scan(
    case_id: str = typer.Option(..., "--case", help="Case ID to scan"),
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
):
    """Scan the case's events for potential ATT&CK technique matches.

    Always a full rescan of every event, not scoped to what was just
    parsed - a technique can be supported by events across multiple
    evidence items. Any investigator-set status from a previous scan is
    preserved.
    """
    from netforensicai.core.attack import scan_case
    from netforensicai.core.case import CaseError, CaseManager
    from netforensicai.core.store import CaseStore

    case_manager = CaseManager(cases_dir)
    try:
        case = case_manager.load(case_id)
    except CaseError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    case_dir = Path(cases_dir) / case.case_id
    with CaseStore(case_dir) as store:
        touched = scan_case(store)

    from netforensicai.core import audit

    audit.record(
        case_dir,
        audit.ATTACK_SCANNED,
        {"techniques_detected": [technique_id for technique_id, _name in touched]},
    )

    if not touched:
        typer.echo("No potential ATT&CK techniques detected.")
        return

    typer.echo(f"Detected {len(touched)} potential technique(s):")
    for technique_id, technique_name in touched:
        typer.echo(f"  {technique_id}: {technique_name}")


@attack_app.command("list")
def attack_list(
    case_id: str = typer.Option(..., "--case", help="Case ID to list techniques for"),
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
):
    """List detected ATT&CK technique mappings for a case."""
    from netforensicai.core.case import CaseError, CaseManager
    from netforensicai.core.store import CaseStore

    case_manager = CaseManager(cases_dir)
    try:
        case = case_manager.load(case_id)
    except CaseError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    case_dir = Path(cases_dir) / case.case_id
    with CaseStore(case_dir) as store:
        techniques = store.list_techniques()

    if not techniques:
        typer.echo(f"No ATT&CK techniques detected for {case.case_id}. Run `netforensic attack scan` first.")
        return

    header = f"{'TECHNIQUE':<14} {'STATUS':<12} {'CONFIDENCE':<10} {'EVENTS':<8} NAME"
    typer.echo(header)
    typer.echo("-" * len(header))
    for t in techniques:
        typer.echo(
            f"{t['technique_id']:<14} {t['status']:<12} {t['confidence']:<10} {t['event_count']:<8} {t['technique_name']}"
        )


@attack_app.command("update")
def attack_update(
    case_id: str = typer.Option(..., "--case", help="Case ID"),
    technique_id: str = typer.Option(..., "--technique", help="Technique ID, e.g. T1059.001"),
    status: str = typer.Option(..., "--status", help="potential, confirmed, or rejected"),
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
):
    """Investigator validation: confirm or reject a detected technique mapping."""
    from datetime import datetime, timezone

    from netforensicai.core.case import CaseError, CaseManager
    from netforensicai.core.store import CaseStore

    valid_statuses = ("potential", "confirmed", "rejected")
    if status not in valid_statuses:
        typer.echo(f"Error: --status must be one of: {', '.join(valid_statuses)}", err=True)
        raise typer.Exit(code=1)

    case_manager = CaseManager(cases_dir)
    try:
        case = case_manager.load(case_id)
    except CaseError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    case_dir = Path(cases_dir) / case.case_id
    with CaseStore(case_dir) as store:
        existing = store.get_technique(technique_id)
        if existing is None:
            typer.echo(f"Error: technique '{technique_id}' has not been detected for this case.", err=True)
            raise typer.Exit(code=1)
        previous_status = existing["status"]
        store.update_technique_status(technique_id, status, datetime.now(timezone.utc))

    from netforensicai.core import audit

    audit.record(
        case_dir,
        audit.ATTACK_UPDATED,
        {"technique_id": technique_id, "from": previous_status, "to": status},
    )

    typer.echo(f"Updated {technique_id}: status={status}")


detections_app = typer.Typer(
    help="Bundled offline detection rules (deterministic, run automatically by `analyze`).",
    no_args_is_help=True,
)
app.add_typer(detections_app, name="detections")


@detections_app.command("list")
def detections_list(
    case_id: str = typer.Option(..., "--case", help="Case ID to list detections for"),
    severity: str = typer.Option(None, "--severity", help="Filter to one severity: low, medium, or high"),
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
):
    """List detections from the last `analyze` run for a case. Detections
    are recomputed automatically every analyze - there's no separate scan
    command; run `netforensic analyze --case ...` again after adding
    evidence or upgrading to a version with new rules."""
    from netforensicai.core.case import CaseError, CaseManager
    from netforensicai.core.store import CaseStore

    if severity and severity not in ("low", "medium", "high"):
        typer.echo("Error: --severity must be one of: low, medium, high", err=True)
        raise typer.Exit(code=1)

    case_manager = CaseManager(cases_dir)
    try:
        case = case_manager.load(case_id)
    except CaseError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    case_dir = Path(cases_dir) / case.case_id
    with CaseStore(case_dir) as store:
        detections = store.list_detections(severity=severity)

    if not detections:
        typer.echo(f"No detections for {case.case_id}. Run `netforensic analyze --case {case.case_id}` first.")
        return

    header = f"{'SEVERITY':<10} {'RULE':<24} {'EVENT':<20} DESCRIPTION"
    typer.echo(header)
    typer.echo("-" * len(header))
    for d in detections:
        typer.echo(f"{d['severity']:<10} {d['rule_id']:<24} {d['event_id']:<20} {d['description']}")


report_app = typer.Typer(help="Generate case reports.", no_args_is_help=True)
app.add_typer(report_app, name="report")


@report_app.command("generate")
def report_generate(
    case_id: str = typer.Option(..., "--case", help="Case ID to generate a report for"),
    format: str = typer.Option("markdown", "--format", help="markdown, json, or html"),
    output: str = typer.Option(
        None, "--output", help="Output file path (defaults to cases/<ID>/reports/report.<ext>)"
    ),
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
):
    """Generate a case report. Never makes an external call - only reflects what's already in the case."""
    from netforensicai.core.case import CaseError, CaseManager
    from netforensicai.core.report import EXTENSION_BY_FORMAT, RENDERERS, build_report

    format_key = format.lower()
    if format_key not in RENDERERS:
        typer.echo(f"Error: unsupported format '{format}'. Choose from: {', '.join(RENDERERS)}", err=True)
        raise typer.Exit(code=1)

    case_manager = CaseManager(cases_dir)
    try:
        case = case_manager.load(case_id)
    except CaseError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    case_dir = Path(cases_dir) / case.case_id
    report = build_report(case, case_dir)
    content = RENDERERS[format_key](report)

    output_path = Path(output) if output else case_dir / "reports" / f"report.{EXTENSION_BY_FORMAT[format_key]}"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")

    from netforensicai.core import audit

    # Recorded here rather than in build_report(): that stays a pure read,
    # and the web UI calls it on every tab view - only writing an actual
    # report artifact is an action worth a custody entry.
    audit.record(
        case_dir,
        audit.REPORT_GENERATED,
        {"format": format_key, "output": str(output_path)},
    )

    typer.echo(f"Generated {format_key} report for {case.case_id}: {output_path}")


@app.command()
def scan(
    pcap_file: str = typer.Argument(..., help="Path to the .pcap file"),
    vt_api: str = typer.Option(
        None, "--vt-api", help="VirusTotal API key (falls back to VT_API_KEY env var)"
    ),
    save_files: bool = typer.Option(False, "--save-files", help="Save extracted files to disk"),
    no_dashboard: bool = typer.Option(False, "--no-dashboard", help="Skip launching the dashboard"),
):
    """Run PCAP deep packet inspection, file extraction, and anomaly detection."""
    import os

    from netforensicai.intel import virustotal
    from netforensicai.parsers.pcap import PcapParseError, PcapParser

    if not os.path.exists(pcap_file):
        typer.echo(f"Error: PCAP file '{pcap_file}' not found.", err=True)
        raise typer.Exit(code=1)

    # `scan` predates case/evidence tracking, so events use a synthetic
    # evidence_id rather than a real Evidence record's id.
    evidence_id = f"scan:{Path(pcap_file).name}"
    output_dir = "extracted_files" if save_files else None

    try:
        events = PcapParser().parse(pcap_file, evidence_id=evidence_id, output_dir=output_dir)
    except PcapParseError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    connections = [e for e in events if e.event_type == "network_connection"]
    files_found = [e for e in events if e.event_type == "file_transfer"]
    anomalies = [e for e in events if e.event_type == "anomaly"]

    if connections:
        logger.info("Top 5 DPI Results:")
        for event in connections[:5]:
            logger.info(f"Source: {event.src_ip}:{event.src_port} -> Destination: {event.dst_ip}:{event.dst_port}")
            logger.info(f"Payload Preview: {event.message}...")
    else:
        logger.warning("No TCP packets found for DPI.")

    logger.info(f"Total Files Found: {len(files_found)}")
    if files_found:
        logger.info("Detected Files:")
        for event in files_found:
            logger.info(f"Stream: {event.raw_event_reference['stream']} | Type: {event.file_name.rsplit('.', 1)[-1]} | Hash: {event.file_hash}")

    if anomalies:
        logger.info(f"Found {len(anomalies)} anomalous packets")
        for event in anomalies[:5]:
            logger.info(f"Packet {event.raw_event_reference['packet_number']}: {event.src_ip} -> {event.dst_ip}")
    else:
        logger.warning("No anomalies detected.")

    api_key = virustotal.get_api_key(vt_api)
    if api_key and connections:
        logger.info("Checking threat intelligence for top IPs...")
        for event in connections[:5]:
            if event.src_ip:
                result = virustotal.check_ip(event.src_ip, api_key)
                if result["malicious"]:
                    logger.warning(
                        f"Malicious IP detected: {event.src_ip} "
                        f"({result['malicious_count']}/{result['total_engines']} engines)"
                    )

    if not no_dashboard and anomalies:
        from netforensicai import dashboard

        dashboard.launch(anomalies)
    else:
        logger.info("Dashboard skipped. Use --no-dashboard to disable or ensure anomalies are detected.")


@app.command("search")
def search_cmd(
    case_id: str = typer.Option(..., "--case", help="Case ID to search within"),
    pattern: str = typer.Argument(..., help="What to look for, e.g. 'flag{' or 'password='"),
    evidence_id: str = typer.Option(None, "--evidence", help="Search only this capture (default: every capture in the case)"),
    mode: str = typer.Option("text", "--mode", help="How to interpret the pattern: text, regex, or hex"),
    case_sensitive: bool = typer.Option(False, "--case-sensitive", help="Match case exactly (text mode)"),
    display_filter: str = typer.Option(None, "--display-filter", help="Narrow the search first, e.g. 'http && ip.addr == 10.0.0.5'"),
    max_hits: int = typer.Option(SEARCH_DEFAULT_MAX_HITS, "--max-hits", help="Stop after this many hits"),
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
):
    """Search the raw bytes of a case's captures for a string, regex, or hex sequence.

    Answers the question the event pipeline structurally cannot: parsing
    normalizes packets into events and does not keep payload, so "where
    does this token appear" has to go back to the capture file. Each hit
    reports a frame number and stream, which `wireshark open` and
    `stream follow` both take directly.
    """
    from netforensicai.core import search as search_module
    from netforensicai.core.case import CaseError, CaseManager
    from netforensicai.core.evidence import EvidenceManager

    case_manager = CaseManager(cases_dir)
    try:
        case = case_manager.load(case_id)
    except CaseError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    case_dir = Path(cases_dir) / case.case_id
    manager = EvidenceManager(case_dir)
    items = [item for item in manager.list() if item.evidence_type == "pcap"]
    if evidence_id:
        items = [item for item in items if item.evidence_id == evidence_id]
        if not items:
            typer.echo(f"Error: no capture evidence {evidence_id} in {case.case_id}.", err=True)
            raise typer.Exit(code=1)
    if not items:
        typer.echo(f"No capture evidence in {case.case_id} to search.")
        return

    total = 0
    for evidence in items:
        try:
            result = search_module.search_capture(
                manager.stored_file_path(evidence.evidence_id),
                pattern,
                mode=mode,
                case_sensitive=case_sensitive,
                max_hits=max_hits,
                display_filter=display_filter,
            )
        except search_module.SearchError as e:
            typer.echo(f"Error: {e}", err=True)
            raise typer.Exit(code=1)

        if not result.hits:
            continue

        typer.echo(f"\n{evidence.evidence_id} ({evidence.filename}) - {len(result.hits)} hit(s)")
        typer.echo(f"  filter: {result.display_filter}")
        for hit in result.hits:
            total += 1
            when = hit.timestamp.isoformat() if hit.timestamp else "unknown"
            stream = f" {hit.protocol.lower()} stream {hit.stream}" if hit.stream is not None else ""
            typer.echo(f"  frame {hit.frame_number} @ {when}  {hit.src} -> {hit.dst}{stream}")
            if hit.excerpt:
                typer.echo(f"    {hit.excerpt}")
        if result.truncated:
            typer.echo(f"  (stopped at --max-hits {max_hits}; there may be more)")

    if total == 0:
        typer.echo(f"No match for {pattern!r} in {len(items)} capture(s).")
        return
    typer.echo(f"\n{total} hit(s). Open one in Wireshark with:")
    typer.echo(f"  netforensic wireshark open --case {case.case_id} --evidence {items[0].evidence_id} --display-filter 'frame.number == N'")


stream_app = typer.Typer(help="Reassemble conversations from a capture.", no_args_is_help=True)
app.add_typer(stream_app, name="stream")


def _resolve_capture(cases_dir, case_id, evidence_id):
    from netforensicai.core.case import CaseError, CaseManager
    from netforensicai.core.evidence import EvidenceError, EvidenceManager

    case_manager = CaseManager(cases_dir)
    try:
        case = case_manager.load(case_id)
    except CaseError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    case_dir = Path(cases_dir) / case.case_id
    manager = EvidenceManager(case_dir)
    if evidence_id:
        try:
            evidence = manager.load(evidence_id)
        except EvidenceError as e:
            typer.echo(f"Error: {e}", err=True)
            raise typer.Exit(code=1)
    else:
        captures = [item for item in manager.list() if item.evidence_type == "pcap"]
        if not captures:
            typer.echo(f"Error: no capture evidence in {case.case_id}.", err=True)
            raise typer.Exit(code=1)
        if len(captures) > 1:
            typer.echo(
                f"Error: {case.case_id} has {len(captures)} captures; pass --evidence to say which.",
                err=True,
            )
            raise typer.Exit(code=1)
        evidence = captures[0]

    if evidence.evidence_type != "pcap":
        typer.echo(f"Error: {evidence.evidence_id} is {evidence.evidence_type}, not a capture.", err=True)
        raise typer.Exit(code=1)
    return case, evidence, manager.stored_file_path(evidence.evidence_id)


@stream_app.command("list")
def stream_list(
    case_id: str = typer.Option(..., "--case", help="Case ID"),
    evidence_id: str = typer.Option(None, "--evidence", help="Capture to list streams from"),
    protocol: str = typer.Option("tcp", "--protocol", help="tcp or udp"),
    display_filter: str = typer.Option(None, "--display-filter", help="Only streams matching this filter"),
    limit: int = typer.Option(25, "--limit", help="How many streams to show"),
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
):
    """List the conversations in a capture, largest first."""
    from netforensicai.core import streams as streams_module

    _case, evidence, path = _resolve_capture(cases_dir, case_id, evidence_id)
    try:
        found = streams_module.list_streams(path, protocol=protocol, display_filter=display_filter, limit=limit)
    except streams_module.StreamError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    if not found:
        typer.echo("No matching streams.")
        return

    typer.echo(f"{evidence.evidence_id} - {len(found)} {protocol} stream(s), largest first")
    header = f"{'STREAM':<8} {'ENDPOINTS':<46} {'PKTS':>7} {'BYTES':>10}  PROTOCOLS"
    typer.echo(header)
    typer.echo("-" * len(header))
    for summary in found:
        endpoints = f"{summary.endpoint_a} -> {summary.endpoint_b}"
        typer.echo(
            f"{summary.stream:<8} {endpoints:<46} {summary.packets:>7,} {summary.bytes:>10,}  "
            f"{', '.join(summary.applications)}"
        )


@stream_app.command("follow")
def stream_follow(
    case_id: str = typer.Option(..., "--case", help="Case ID"),
    index: int = typer.Argument(..., help="Stream index (see `stream list`, or a search hit)"),
    evidence_id: str = typer.Option(None, "--evidence", help="Capture the stream is in"),
    protocol: str = typer.Option("tcp", "--protocol", help="tcp or udp"),
    max_bytes: int = typer.Option(
        STREAM_DEFAULT_MAX_BYTES, "--max-bytes", help="Truncate the conversation at this many bytes"
    ),
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
):
    """Reassemble one conversation and print it as the two sides exchanged it."""
    from netforensicai.core import streams as streams_module

    _case, _evidence, path = _resolve_capture(cases_dir, case_id, evidence_id)
    try:
        followed = streams_module.follow_stream(path, protocol=protocol, index=index, max_bytes=max_bytes)
    except streams_module.StreamError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"{protocol} stream {followed.stream}")
    typer.echo(f"  A: {followed.node_a}")
    typer.echo(f"  B: {followed.node_b}")
    for turn in followed.turns:
        node = followed.node_a if turn.sender == "a" else followed.node_b
        typer.echo(f"\n--- {node} ({turn.byte_count} bytes) ---")
        typer.echo(turn.text)
    if followed.truncated:
        typer.echo(f"\n(truncated at --max-bytes {max_bytes})")


@app.command("chat")
def chat_cmd(
    case_id: str = typer.Option(..., "--case", help="Case ID to ask about"),
    question: str = typer.Argument(None, help="Your question (omit for an interactive session)"),
    provider: str = typer.Option("anthropic", "--ai-provider", help="anthropic, openai, ollama, or gemini"),
    ai_model: str = typer.Option(None, "--model", help="Override the provider's default model"),
    api_key: str = typer.Option(None, "--api-key", help="API key (falls back to env var, then saved config)"),
    base_url: str = typer.Option(None, "--ollama-url", help="Ollama base URL"),
    max_steps: int = typer.Option(
        CHAT_DEFAULT_MAX_STEPS, "--max-steps", help="Tool calls allowed before the model must answer"
    ),
    show_steps: bool = typer.Option(True, "--steps/--no-steps", help="Show which tools were called"),
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
):
    """Ask a question about a case. The assistant retrieves evidence itself.

    Every claim in the answer is checked against what its tools actually
    returned. An answer citing anything else is refused outright rather
    than shown with a caveat - see core/chat.py.

    Optional and explicitly invoked, like every AI feature here: nothing
    calls a provider unless you run this.
    """
    from netforensicai.core import chat as chat_module
    from netforensicai.core.case import CaseError, CaseManager

    case_manager = CaseManager(cases_dir)
    try:
        case = case_manager.load(case_id)
    except CaseError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    case_dir = Path(cases_dir) / case.case_id

    def answer_one(text):
        try:
            result = chat_module.ask(
                text,
                case_dir,
                provider=provider,
                api_key=api_key,
                model=ai_model,
                base_url=base_url,
                max_steps=max_steps,
            )
        except chat_module.ChatError as e:
            typer.echo(f"Error: {e}", err=True)
            return False

        if show_steps and result.steps:
            typer.echo("\nRetrieved:")
            for step in result.steps:
                detail = step.error or step.summary
                typer.echo(f"  {step.tool}({_compact(step.arguments)}) -> {detail}")

        typer.echo(f"\n{result.answer}")
        if not result.evidence_sufficient:
            typer.echo("\n  (the assistant judged the available evidence insufficient)")
        if result.citations:
            typer.echo("\nCited evidence:")
            for citation in result.citations:
                typer.echo(f"  {citation.kind:<10} {citation.evidence_id}  {citation.reference}")
        else:
            typer.echo("\n  (no evidence cited)")
        return True

    if question:
        if not answer_one(question):
            raise typer.Exit(code=1)
        return

    typer.echo(f"Chat about {case.case_id} ({case.name}). Ctrl+C or an empty line to finish.")
    while True:
        try:
            text = typer.prompt("\n?", default="", show_default=False)
        except (KeyboardInterrupt, EOFError):
            typer.echo("")
            return
        if not text.strip():
            return
        answer_one(text)


def _compact(arguments):
    if not arguments:
        return ""
    return ", ".join(f"{key}={value!r}" for key, value in arguments.items())


ctf_app = typer.Typer(
    help="Triage presets: the first questions to ask an unfamiliar capture.",
    no_args_is_help=True,
)
app.add_typer(ctf_app, name="ctf")


def _print_candidates(candidates, truncated_categories):
    if not candidates:
        typer.echo("\nNothing matched the flag, credential or secret patterns.")
        return
    typer.echo(f"\nCandidates ({len(candidates)}) - these are strings that matched a pattern, not verdicts:")
    for category in ("flags", "credentials", "secrets"):
        rows = [c for c in candidates if c.category == category]
        if not rows:
            continue
        typer.echo(f"\n  {category.upper()}")
        for row in rows:
            where = f"frame {row.frame_number}"
            if row.stream is not None:
                where += f", {(row.protocol or 'tcp').lower()} stream {row.stream}"
            typer.echo(f"    [{row.pattern}] {row.value}")
            typer.echo(f"        {where}  {row.src or '?'} -> {row.dst or '?'}")
    for category in truncated_categories:
        typer.echo(f"\n  (stopped early on {category}; raise --max-hits for more)")


@ctf_app.command("triage")
def ctf_triage(
    case_id: str = typer.Option(..., "--case", help="Case ID"),
    evidence_id: str = typer.Option(None, "--evidence", help="Capture to triage"),
    max_hits: int = typer.Option(
        CTF_DEFAULT_MAX_HITS, "--max-hits", help="Stop each category after this many matching packets"
    ),
    extract_to: str = typer.Option(
        None, "--extract-to", help="Write recovered files here (default: report them without saving)"
    ),
    display_filter: str = typer.Option(None, "--display-filter", help="Narrow triage to matching traffic"),
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
):
    """Run every preset over a capture: protocols, flags, credentials, secrets, files, conversations.

    Read-only. Nothing here creates a finding - turning a candidate into
    one stays an explicit investigator action, as everywhere else.
    """
    from netforensicai.core import ctf as ctf_module

    _case, evidence, path = _resolve_capture(cases_dir, case_id, evidence_id)
    try:
        report = ctf_module.triage(
            path, max_hits=max_hits, output_dir=extract_to, display_filter=display_filter
        )
    except ctf_module.CtfError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"Triage of {evidence.evidence_id} ({evidence.filename})")

    typer.echo("\nProtocols:")
    for protocol in report.protocols:
        indent = "  " * protocol.depth
        line = f"  {indent}{protocol.protocol:<16} {protocol.frames:>8,} frames  {protocol.bytes:>11,} bytes"
        typer.echo(line)
        if protocol.note:
            typer.echo(f"  {indent}  -> {protocol.note}")

    _print_candidates(report.candidates, report.truncated_categories)

    if report.files:
        typer.echo(f"\nRecoverable files ({len(report.files)}):")
        for item in report.files:
            typer.echo(f"  {item.protocol}/{item.name}  {item.size:,} bytes  sha256={item.sha256[:16]}...")
            if item.path:
                typer.echo(f"      saved to {item.path}")
        if not extract_to:
            typer.echo("  (pass --extract-to DIR to save them)")

    if report.top_streams:
        typer.echo("\nLargest conversations:")
        for summary in report.top_streams:
            typer.echo(
                f"  stream {summary.stream:<6} {summary.endpoint_a} -> {summary.endpoint_b}  "
                f"{summary.packets:,} pkts, {summary.bytes:,} bytes  {', '.join(summary.applications)}"
            )
        typer.echo(f"\nRead one with:\n  netforensic stream follow --case {case_id} {report.top_streams[0].stream}")


@ctf_app.command("hunt")
def ctf_hunt(
    case_id: str = typer.Option(..., "--case", help="Case ID"),
    category: str = typer.Option("flags", "--category", help="flags, credentials, or secrets"),
    evidence_id: str = typer.Option(None, "--evidence", help="Capture to hunt through"),
    max_hits: int = typer.Option(CTF_DEFAULT_MAX_HITS, "--max-hits", help="Stop after this many matching packets"),
    display_filter: str = typer.Option(None, "--display-filter", help="Narrow the hunt to matching traffic"),
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
):
    """Hunt one category of interesting string: flags, credentials, or secrets."""
    from netforensicai.core import ctf as ctf_module

    _case, _evidence, path = _resolve_capture(cases_dir, case_id, evidence_id)
    try:
        candidates, truncated = ctf_module.hunt(
            path, category, max_hits=max_hits, display_filter=display_filter
        )
    except ctf_module.CtfError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    _print_candidates(candidates, [category] if truncated else [])


@ctf_app.command("patterns")
def ctf_patterns():
    """Show the patterns each category hunts for."""
    from netforensicai.core import ctf as ctf_module

    for category, patterns in ctf_module.CATEGORIES.items():
        typer.echo(f"\n{category}:")
        for name, expression in patterns.items():
            typer.echo(f"  {name:<18} {expression}")


wireshark_app = typer.Typer(
    help="Wireshark integration: engine status, display filters, and opening evidence in the GUI.",
    no_args_is_help=True,
)
app.add_typer(wireshark_app, name="wireshark")


def _resolve_pcap_evidence(case_dir, evidence_id):
    """Load a pcap evidence item and return (evidence, stored_path).

    Always resolves to the *stored* copy under the case rather than
    whatever path the file was added from: the stored copy is the one that
    was hashed into the chain of custody, so it is the only one a pivot or
    a slice may be taken from.
    """
    from netforensicai.core.evidence import EvidenceError, EvidenceManager

    manager = EvidenceManager(case_dir)
    try:
        evidence = manager.load(evidence_id)
    except EvidenceError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)
    if evidence.evidence_type != "pcap":
        typer.echo(
            f"Error: {evidence_id} is {evidence.evidence_type} evidence, not a capture file.",
            err=True,
        )
        raise typer.Exit(code=1)
    return evidence, manager.stored_file_path(evidence.evidence_id)


@wireshark_app.command("status")
def wireshark_status():
    """Show which Wireshark tools were found and which engines are in use."""
    from netforensicai.core import capture as capture_module
    from netforensicai.integrations import wireshark
    from netforensicai.parsers import pcap_engine

    info = wireshark.status()
    if not info["available"]:
        typer.echo("Wireshark: not found.")
        typer.echo(
            "  NetForensicAI works without it - pcap parsing falls back to the built-in scapy "
            "engine. Install Wireshark to get its ~3000 dissectors, object export, display "
            "filters and the GUI pivot."
        )
        typer.echo("  If it is installed somewhere unusual, set NETFORENSIC_WIRESHARK_DIR.")
        raise typer.Exit(code=1)

    typer.echo(f"Wireshark: {info['version']}")
    typer.echo(f"  tshark:  {info['tshark']}")
    typer.echo(f"  dumpcap: {info['dumpcap'] or '(not found)'}")
    typer.echo(f"  GUI:     {info['gui'] or '(not found)'}")

    engine = pcap_engine.engine_status()
    typer.echo(f"Parse engine:   {engine['selected'] or 'unavailable'} (requested: {engine['requested']})")
    if engine["error"]:
        typer.echo(f"  {engine['error']}")
    try:
        typer.echo(f"Capture engine: {capture_module.resolve_capture_engine()}")
    except capture_module.CaptureError as e:
        typer.echo(f"Capture engine: unavailable - {e}")


@wireshark_app.command("check-filter")
def wireshark_check_filter(
    display_filter: str = typer.Argument(..., help="Display filter to validate, e.g. 'dns.qry.name contains \"evil\"'"),
):
    """Validate a Wireshark display filter without running it against a capture."""
    from netforensicai.integrations import wireshark

    valid, error = wireshark.validate_display_filter(display_filter)
    if valid:
        typer.echo(f"Valid: {display_filter}")
        return
    typer.echo(f"Invalid: {error}", err=True)
    raise typer.Exit(code=1)


@wireshark_app.command("open")
def wireshark_open(
    case_id: str = typer.Option(..., "--case", help="Case ID the evidence belongs to"),
    evidence_id: str = typer.Option(None, "--evidence", help="Capture evidence to open (e.g. EV-0001)"),
    event_id: str = typer.Option(
        None,
        "--event",
        help="Open the capture this event came from, pre-filtered to the exact packets behind it",
    ),
    display_filter: str = typer.Option(
        None, "--display-filter", help="Display filter to open with (overrides the one derived from --event)"
    ),
    print_only: bool = typer.Option(
        False, "--print", help="Print the command instead of launching the GUI"
    ),
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
):
    """Open case evidence in the Wireshark GUI, pre-filtered to a finding's packets.

    This is the pivot out of the platform and into packet-level review:
    --event derives the filter from the event's own recorded frame numbers,
    so what opens is exactly the traffic the finding was drawn from rather
    than something that merely resembles it.
    """
    from netforensicai.core.case import CaseError, CaseManager
    from netforensicai.core.store import CaseStore
    from netforensicai.integrations import wireshark

    if not evidence_id and not event_id:
        typer.echo("Error: pass --evidence or --event.", err=True)
        raise typer.Exit(code=1)

    case_manager = CaseManager(cases_dir)
    try:
        case = case_manager.load(case_id)
    except CaseError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)
    case_dir = Path(cases_dir) / case.case_id

    derived_filter = None
    if event_id:
        with CaseStore(case_dir) as store:
            event = store.get_event(event_id)
        if event is None:
            typer.echo(f"Error: no event {event_id} in {case.case_id}.", err=True)
            raise typer.Exit(code=1)
        evidence_id = evidence_id or event.evidence_id
        derived_filter = wireshark.filter_for_event(event)
        if derived_filter is None and not display_filter:
            typer.echo(
                f"Note: {event_id} carries no packet reference to pivot on; opening the whole capture."
            )

    evidence, stored_path = _resolve_pcap_evidence(case_dir, evidence_id)
    effective_filter = display_filter or derived_filter

    if print_only:
        typer.echo(wireshark.gui_command(stored_path, effective_filter))
        return

    try:
        wireshark.open_gui(stored_path, effective_filter)
    except wireshark.WiresharkError as e:
        typer.echo(f"Error: {e}", err=True)
        typer.echo(f"Run this yourself instead:\n  {wireshark.gui_command(stored_path, effective_filter)}")
        raise typer.Exit(code=1)

    typer.echo(f"Opened {evidence.evidence_id} in Wireshark.")
    if effective_filter:
        typer.echo(f"  Display filter: {effective_filter}")


@wireshark_app.command("slice")
def wireshark_slice(
    case_id: str = typer.Option(..., "--case", help="Case ID the evidence belongs to"),
    evidence_id: str = typer.Option(..., "--evidence", help="Capture evidence to slice (e.g. EV-0001)"),
    display_filter: str = typer.Option(..., "--display-filter", help="Wireshark display filter selecting the packets to keep"),
    add_as_evidence: bool = typer.Option(
        True,
        "--add-as-evidence/--no-add-as-evidence",
        help="Add the slice back into the case as its own hashed evidence item",
    ),
    output: str = typer.Option(None, "--output", help="Where to write the slice (defaults to a file in the case directory)"),
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
):
    """Carve the packets matching a display filter into a new capture file.

    The slice is a real capture, not a view, so by default it goes back
    into the case through the normal evidence path - hashed, recorded in
    the audit trail, and analyzable on its own. That is what makes
    "I filtered the capture down to this" reproducible by someone else
    later, which a screenshot of a filtered GUI is not.
    """
    from netforensicai.core.case import CaseError, CaseManager
    from netforensicai.core.evidence import EvidenceError, EvidenceManager
    from netforensicai.integrations import wireshark

    case_manager = CaseManager(cases_dir)
    try:
        case = case_manager.load(case_id)
    except CaseError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)
    case_dir = Path(cases_dir) / case.case_id

    evidence, stored_path = _resolve_pcap_evidence(case_dir, evidence_id)
    destination = Path(output) if output else case_dir / "slices" / f"{evidence.evidence_id}-slice.pcap"

    try:
        slice_path, packet_count = wireshark.extract_slice(stored_path, display_filter, destination)
    except wireshark.WiresharkError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    if packet_count == 0:
        # An empty slice is a valid answer to the filter, but adding it as
        # evidence would put an empty capture into the chain of custody
        # and imply something was found.
        slice_path.unlink(missing_ok=True)
        typer.echo(f"No packets in {evidence.evidence_id} matched: {display_filter}")
        return

    typer.echo(f"Wrote {packet_count} packet(s) to {slice_path}")
    if not add_as_evidence:
        return

    try:
        new_evidence = EvidenceManager(case_dir).add(slice_path, case_id=case.case_id)
    except EvidenceError as e:
        typer.echo(f"Error adding the slice as evidence: {e}", err=True)
        raise typer.Exit(code=1)
    case_manager.register_evidence(case.case_id, new_evidence.evidence_id)

    # The slice's own evidence record says only that a pcap was added. The
    # audit entry is what ties it back to the capture and the exact filter
    # it came from - without it the derived evidence would be untraceable
    # to its parent, which is the one thing a derived artifact must not be.
    from netforensicai.core import audit

    audit.record(
        case_dir,
        audit.EVIDENCE_SLICED,
        {
            "evidence_id": new_evidence.evidence_id,
            "derived_from": evidence.evidence_id,
            "display_filter": display_filter,
            "packet_count": packet_count,
        },
    )
    typer.echo(f"Added as {new_evidence.evidence_id} - parse it with:")
    typer.echo(f"  netforensic parse --case {case.case_id} --evidence {new_evidence.evidence_id}")


@app.command("web")
def web(
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address (127.0.0.1 = local machine only)"),
    port: int = typer.Option(8000, "--port", help="Port to listen on"),
):
    """Launch the local web UI: browse cases, upload/analyze evidence,
    investigate entities, manage findings, run live capture, and generate
    reports - all calling the same core modules the CLI uses."""
    from netforensicai.web.app import create_app

    if host not in ("127.0.0.1", "localhost"):
        typer.echo(
            f"WARNING: binding to {host} may expose this UI to other machines on the network. "
            "There is no authentication - only do this on a trusted network."
        )

    flask_app = create_app(cases_dir)
    typer.echo(f"NetForensicAI web UI running at http://{host}:{port} (Ctrl+C to stop)")
    # Single-threaded deliberately: CaseStore/DuckDB is single-writer, and
    # this is a local single-user tool, not a production multi-user
    # server - see netforensicai/web/app.py's module docstring.
    flask_app.run(host=host, port=port, debug=False, threaded=False)


@app.command("capture")
def capture_cmd(
    case_id: str = typer.Option(None, "--case", help="Case ID to capture into"),
    interface: str = typer.Option(None, "--interface", help="Network interface to capture on (see --list-interfaces)"),
    bpf_filter: str = typer.Option(None, "--filter", help="BPF filter, e.g. 'tcp port 443'"),
    rotate_seconds: int = typer.Option(
        30,
        "--rotate-seconds",
        help="Seconds of traffic per capture window before it's rotated and ingested as evidence",
    ),
    list_interfaces_flag: bool = typer.Option(
        False, "--list-interfaces", help="List available network interfaces and exit"
    ),
    engine: str = typer.Option(
        "auto",
        "--engine",
        help="Capture backend: 'auto' (dumpcap when Wireshark is installed), 'dumpcap', or 'scapy'",
    ),
    cases_dir: str = typer.Option(
        DEFAULT_CASES_DIR,
        "--cases-dir",
        envvar="NETFORENSIC_CASES_DIR",
        help="Root directory for case storage",
    ),
):
    """Capture live traffic into rotating pcap windows, auto-ingested as evidence as each completes.

    Needs a packet-capture driver (Npcap on Windows, libpcap on Linux/macOS)
    and elevated privileges - this command does not install or grant either.
    """
    import time

    from netforensicai.core import capture as capture_module
    from netforensicai.core.case import CaseError, CaseManager

    if list_interfaces_flag:
        try:
            interfaces = capture_module.list_interfaces()
        except Exception as e:
            typer.echo(f"Error listing interfaces: {e}", err=True)
            raise typer.Exit(code=1)
        for iface in interfaces:
            # The description is what makes a Windows \Device\NPF_{GUID}
            # identifiable as a particular NIC, so print it when dumpcap
            # supplied one.
            description = iface.get("description")
            typer.echo(f"{iface['name']}  ({description})" if description else iface["name"])
        return

    if not case_id:
        typer.echo("Error: --case is required (unless using --list-interfaces).", err=True)
        raise typer.Exit(code=1)

    case_manager = CaseManager(cases_dir)
    try:
        case = case_manager.load(case_id)
    except CaseError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    case_dir = Path(cases_dir) / case.case_id
    try:
        selected_engine = capture_module.resolve_capture_engine(engine)
    except capture_module.CaptureError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    session_class = (
        capture_module.DumpcapCaptureSession
        if selected_engine == capture_module.ENGINE_DUMPCAP
        else capture_module.CaptureSession
    )
    session = session_class(
        case.case_id, case_dir, case_manager, interface=interface, bpf_filter=bpf_filter, rotate_seconds=rotate_seconds
    )

    try:
        session.start()
    except capture_module.CaptureError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    typer.echo(
        f"Capturing into {case.case_id} on interface {interface or '(default)'} "
        f"using the {selected_engine} engine - Ctrl+C to stop."
    )
    typer.echo(f"Rotating every {rotate_seconds}s; each finished window is ingested as evidence automatically.")
    try:
        while True:
            time.sleep(2)
            snap = session.snapshot()
            typer.echo(
                f"  window: {snap['window_packet_count']} packets ({snap['window_elapsed_seconds']:.0f}s) "
                f"| total: {snap['total_packet_count']} packets"
            )
    except KeyboardInterrupt:
        typer.echo("Stopping capture...")
        session.stop()
        typer.echo("Stopped.")


def main():
    try:
        app()
    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()
