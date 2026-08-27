"""NetForensicAI CLI entrypoint.

`scan` is the pre-case-management pcap workflow carried over from the
original netforensicai.py script. Case/evidence/timeline/investigate
subcommands land in later steps of the DFIR-platform migration.
"""

import logging
import sys
from pathlib import Path

import typer

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

DEFAULT_CASES_DIR = "cases"

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


def _parse_one_evidence(evidence, case_dir, case_manager, case_id, store):
    """Parse one evidence item, persist its events + extracted entities into
    `store`, and register any newly saved artifact files against the case.

    Returns (event_count, entity_count, error). error is None on success.
    """
    import os

    from netforensicai.core.entities import extract_and_store
    from netforensicai.parsers import base, load_parsers

    load_parsers()
    parser = base.get_parser(evidence.evidence_type)
    if parser is None:
        return None, None, f"No parser registered for evidence type '{evidence.evidence_type}'"

    from netforensicai.core.evidence import EvidenceManager

    stored_path = EvidenceManager(case_dir).stored_file_path(evidence.evidence_id)
    output_dir = case_dir / "artifacts" / evidence.evidence_id

    try:
        events = parser.parse(stored_path, evidence_id=evidence.evidence_id, output_dir=str(output_dir))
    except Exception as e:
        return None, None, str(e)

    store.replace_events_for_evidence(evidence.evidence_id, events)
    entity_count = extract_and_store(store, events)

    for event in events:
        if event.event_type == "file_transfer" and event.file_path:
            relative_path = os.path.relpath(event.file_path, case_dir).replace(os.sep, "/")
            case_manager.register_artifact(case_id, relative_path)

    return len(events), entity_count, None


@app.command("parse")
def parse_evidence(
    case_id: str = typer.Option(..., "--case", help="Case ID the evidence belongs to"),
    evidence_id: str = typer.Option(..., "--evidence", help="Evidence ID to parse (e.g. EV-0001)"),
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

    with CaseStore(case_dir) as store:
        event_count, entity_count, error = _parse_one_evidence(evidence, case_dir, case_manager, case.case_id, store)

    if error:
        typer.echo(f"Error parsing {evidence_id}: {error}", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"Parsed {evidence_id}: {event_count} events, {entity_count} entities")


@app.command("analyze")
def analyze_case(
    case_id: str = typer.Option(..., "--case", help="Case ID to analyze"),
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

    total_events = 0
    total_entities = 0
    with CaseStore(case_dir) as store:
        for evidence in items:
            event_count, entity_count, error = _parse_one_evidence(evidence, case_dir, case_manager, case.case_id, store)
            if error:
                typer.echo(f"  {evidence.evidence_id} ({evidence.evidence_type}): skipped - {error}")
                continue
            typer.echo(f"  {evidence.evidence_id} ({evidence.evidence_type}): {event_count} events, {entity_count} entities")
            total_events += event_count
            total_entities += entity_count

        # Correlation is case-wide (crosses evidence boundaries), so it
        # always runs as a full rebuild over everything now in the store,
        # not just what was parsed in this invocation.
        links = correlate_case(store)
        related_count = sum(1 for link in links if link["relationship_type"] == RELATED)
        possible_count = sum(1 for link in links if link["relationship_type"] == POSSIBLE_RELATIONSHIP)

    typer.echo(f"Analysis complete for {case.case_id}: {total_events} events, {total_entities} distinct entities")
    typer.echo(f"Correlation: {related_count} related, {possible_count} possible_relationship (time-proximity only)")


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
        if entity_type == "ip_address":
            from netforensicai.intel import virustotal

            api_key = virustotal.get_api_key(vt_api)
            if api_key:
                malicious = virustotal.check_ip(value, api_key)
                typer.echo(f"  VirusTotal: {'FLAGGED MALICIOUS' if malicious else 'not flagged malicious'}")
            else:
                typer.echo("  VirusTotal: not checked (no API key - use --vt-api or set VT_API_KEY)")
        else:
            typer.echo("  (no threat intelligence source available for this entity type yet)")


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
            if event.src_ip and virustotal.check_ip(event.src_ip, api_key):
                logger.warning(f"Malicious IP detected: {event.src_ip}")

    if not no_dashboard and anomalies:
        from netforensicai import dashboard

        dashboard.launch(anomalies)
    else:
        logger.info("Dashboard skipped. Use --no-dashboard to disable or ensure anomalies are detected.")


def main():
    try:
        app()
    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()
