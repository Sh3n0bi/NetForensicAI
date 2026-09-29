"""Generate a synthetic incident capture for demos, tests and evaluation.

The generator itself lives in the package (netforensicai/demo.py) so that
`netforensic demo` works from a PyPI install; this script stays so existing
instructions and samples/generate_benign.py keep working.

    python samples/generate_incident.py -o incident.pcap
"""

try:
    from netforensicai.demo import (  # noqa: F401 - re-exported for generate_benign.py and tests
        BAD_DOMAIN,
        BENIGN,
        DROP,
        PASSWORD,
        RESOLVER,
        STAGER,
        START,
        VICTIM,
        Clock,
        Flow,
        build,
        dns,
        http,
        main,
        write_capture,
    )
except ImportError:  # pragma: no cover - the message is the whole point
    raise SystemExit("This script needs scapy: pip install -e '.[pcap]'")


if __name__ == "__main__":
    main()
