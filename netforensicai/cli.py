"""NetForensicAI CLI entrypoint.

`scan` is the pre-case-management pcap workflow carried over from the
original netforensicai.py script. Case/evidence/timeline/investigate
subcommands land in later steps of the DFIR-platform migration.
"""

import logging
import sys

import typer

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

app = typer.Typer(
    name="netforensic",
    help="NetForensicAI - local-first DFIR investigation platform.",
    no_args_is_help=True,
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
