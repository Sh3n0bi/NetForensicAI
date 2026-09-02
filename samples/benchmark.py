"""Measure what this actually costs to run: throughput, memory, and where
the time goes.

WHY MEASURED AND NOT ESTIMATED. The first time this pipeline was profiled,
all three of the obvious suspects were wrong. Dissection - the part that
looks expensive, shells out to another process and parses JSON - was 6% of
the run. Entity storage, which nobody thinks about, was 66%. Any capacity
answer given from intuition would have been wrong in the direction that
matters, so the answer is generated here instead of asserted.

CORES. The pipeline is single-threaded by design and the store is DuckDB,
which is single-writer. Adding processes does not divide the wall time,
because the bottleneck is a serial write path rather than the CPU. What
more cores DO help with is running several cases at once, which is the
shape most investigations actually have. This script reports the
single-case figure, since that is the one that is easy to overstate.

  python samples/benchmark.py --scale 20 40 80

Each scale is generated, ingested, correlated and scanned, and the run
reports packets/sec, MB/min, peak memory and the split between stages.
"""

import argparse
import gc
import importlib.util
import shutil
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

SAMPLES = Path(__file__).resolve().parent
sys.path.insert(0, str(SAMPLES))


def _load(name):
    spec = importlib.util.spec_from_file_location(name, SAMPLES / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class Stage:
    """Wall time per stage. Deliberately coarse - the useful question is
    which stage dominates, not which function does."""

    def __init__(self):
        self.times = {}

    def __call__(self, name):
        self.name = name
        return self

    def __enter__(self):
        self.start = time.perf_counter()
        return self

    def __exit__(self, *exc):
        self.times[self.name] = self.times.get(self.name, 0.0) + (time.perf_counter() - self.start)
        return False


def run_once(capture, engine):
    from netforensicai.core.case import CaseManager
    from netforensicai.core.correlation import correlate_case
    from netforensicai.core.detections import scan_case
    from netforensicai.core.evidence import EvidenceManager
    from netforensicai.core.store import CaseStore
    from netforensicai.core import narrative as narrative_module, pipeline

    root = Path(tempfile.mkdtemp(prefix="nfai-bench-"))
    stage = Stage()
    try:
        manager = CaseManager(root / "cases")
        case = manager.create(name="Benchmark", investigator="bench")
        case_dir = manager.cases_dir / case.case_id

        with stage("ingest"):
            evidence = EvidenceManager(case_dir).add(capture, case_id=case.case_id)
            manager.register_evidence(case.case_id, evidence.evidence_id)

        gc.collect()
        tracemalloc.start()
        with CaseStore(case_dir) as store:
            with stage("parse+entities"):
                events, entities, error = pipeline.parse_evidence_item(
                    evidence, case_dir, manager, case.case_id, store
                )
                if error:
                    raise RuntimeError(error)
            with stage("correlate"):
                correlate_case(store)
            with stage("detect"):
                detections = scan_case(store)
            with stage("narrate"):
                narrative_module.build(store)
        _current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        return {
            "events": events,
            "entities": entities,
            "detections": len(detections),
            "peak_mb": peak / 1_048_576,
            "stages": stage.times,
            "total": sum(stage.times.values()),
        }
    finally:
        shutil.rmtree(root, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--scale", type=int, nargs="+", default=[10, 20, 40])
    parser.add_argument("--engine", default=None, help="scapy or tshark (default: auto)")
    args = parser.parse_args()

    import os

    if args.engine:
        os.environ["NETFORENSIC_PCAP_ENGINE"] = args.engine

    from scapy.all import wrpcap

    _load("generate_incident")
    benign = _load("generate_benign")

    print(f"{'packets':>9} {'MB':>7} {'events':>8} {'sec':>7} {'pkt/s':>9} {'MB/min':>8} {'peak MB':>8}")
    print("-" * 62)

    workdir = Path(tempfile.mkdtemp(prefix="nfai-caps-"))
    try:
        for scale in args.scale:
            packets = benign.build(scale=scale)
            capture = workdir / f"bench-{scale}.pcap"
            wrpcap(str(capture), packets)
            size_mb = capture.stat().st_size / 1_048_576

            result = run_once(capture, args.engine)
            seconds = result["total"]
            print(
                f"{len(packets):>9,} {size_mb:>7.1f} {result['events']:>8,} {seconds:>7.1f} "
                f"{len(packets) / seconds:>9,.0f} {size_mb / seconds * 60:>8.1f} "
                f"{result['peak_mb']:>8.0f}"
            )
            share = {k: v / seconds for k, v in result["stages"].items()}
            print("           " + "  ".join(f"{k} {v:.0%}" for k, v in sorted(
                share.items(), key=lambda kv: -kv[1])))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
