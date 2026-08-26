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
    from netforensicai.intel import virustotal
    from netforensicai.parsers.pcap import PcapAnalyzer

    tool = PcapAnalyzer(pcap_file)

    dpi_results = tool.deep_packet_inspection()
    if dpi_results:
        logger.info("Top 5 DPI Results:")
        for result in dpi_results[:5]:
            logger.info(
                f"Source: {result['src_ip']}:{result['src_port']} -> "
                f"Destination: {result['dst_ip']}:{result['dst_port']}"
            )
            logger.info(f"Payload Preview: {result['payload']}...")
    else:
        logger.warning("No TCP packets found for DPI.")

    files_found = tool.extract_files(save_files=save_files)
    logger.info(f"Total Files Found: {len(files_found)}")
    if files_found:
        logger.info("Detected Files:")
        for file in files_found:
            logger.info(
                f"Stream: {file['stream']} | Type: {file['file_type']} | Size: {file['size_bytes']} bytes"
            )

    anomalies = tool.anomaly_detection()
    if not anomalies.empty:
        logger.info("Anomalies Detected:")
        logger.info(anomalies.head().to_string())
    else:
        logger.warning("No anomalies detected.")

    api_key = virustotal.get_api_key(vt_api)
    if api_key and dpi_results:
        logger.info("Checking threat intelligence for top IPs...")
        for result in dpi_results[:5]:
            if virustotal.check_ip(result["src_ip"], api_key):
                logger.warning(f"Malicious IP detected: {result['src_ip']}")

    if not no_dashboard and not anomalies.empty:
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
