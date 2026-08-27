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

    typer.echo(f"Analysis complete for {case.case_id}: {total_events} events, {total_entities} distinct entities")


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
