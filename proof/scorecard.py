#!/usr/bin/env python3
"""Reproducible scorecard for NetForensicAI.

One command re-measures everything that can be MEASURED about the project and
prints each number next to a target and a status. Re-run it after every change
to show before/after. It deliberately does not compute a 1-10 "rating": ratings
are judgement, measurements are not.

    python proof/scorecard.py                  # everything except slow extras
    python proof/scorecard.py --fast           # skip the full test suite
    python proof/scorecard.py --bench          # add a throughput benchmark
    python proof/scorecard.py --json out.json  # machine-readable results
    python proof/scorecard.py --strict         # exit 1 if any check FAILs

Statuses:  PASS  meets the target
           WARN  below target but not a defect (see note)
           FAIL  a confirmed gap (the matching test in tests/test_proof_gaps.py fails)
           INFO  a measurement with no target
           SKIP  a tool needed for the check is not installed

Optional tools (pytest-cov, ruff, mypy, bandit) are used when installed:
    pip install -e ".[dev,web,evtx,pcap,intel,ai]" mypy bandit cryptography
"""

import argparse
import ast
import json
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "netforensicai"

RESULTS = []


def add(category, check, value, target, status, note=""):
    RESULTS.append(
        {
            "category": category,
            "check": check,
            "value": str(value),
            "target": str(target),
            "status": status,
            "note": note,
        }
    )


def run(cmd, timeout=1800):
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout + proc.stderr


def module_available(name):
    code, _ = run([sys.executable, "-c", f"import {name}"], timeout=60)
    return code == 0


def guarded(func):
    """A broken check must never take the whole scorecard down."""

    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as exc:
            add("scorecard", func.__name__, "error", "-", "FAIL", f"{type(exc).__name__}: {exc}")

    return wrapper


# --------------------------------------------------------------------------
# Environment
# --------------------------------------------------------------------------


def environment():
    _, rev = run(["git", "rev-parse", "--short", "HEAD"], timeout=30)
    _, branch = run(["git", "branch", "--show-current"], timeout=30)
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "git": f"{branch.strip()}@{rev.strip()}",
        "tshark_installed": shutil.which("tshark") is not None,
    }


# --------------------------------------------------------------------------
# Tests and coverage
# --------------------------------------------------------------------------


@guarded
def check_tests(env):
    cov_json = Path(tempfile.mkdtemp()) / "cov.json"
    cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"]
    has_cov = module_available("pytest_cov")
    if has_cov:
        cmd += ["--cov=netforensicai", f"--cov-report=json:{cov_json}"]
    started = time.time()
    code, out = run(cmd)
    elapsed = time.time() - started

    summary = next((ln for ln in reversed(out.splitlines()) if re.search(r"\d+ (passed|failed|error)", ln)), "")
    tally = {word: int(n) for n, word in re.findall(r"(\d+) (passed|failed|skipped|xfailed|xpassed|errors?)", summary)}
    failed = tally.get("failed", 0) + tally.get("error", 0) + tally.get("errors", 0) + tally.get("xpassed", 0)

    add(
        "tests",
        "suite result",
        summary.strip("= ") or f"exit {code}",
        "0 failed",
        "PASS" if code == 0 and not failed else "FAIL",
    )
    add("tests", "tests passed", tally.get("passed", 0), ">0", "INFO")
    skipped = tally.get("skipped", 0)
    note = (
        "tshark not installed: its tests only run in the project's CI `wireshark` job"
        if not env["tshark_installed"]
        else ""
    )
    add("tests", "tests skipped", skipped, "0", "WARN" if skipped else "PASS", note)
    add("tests", "suite runtime (s)", f"{elapsed:.0f}", "-", "INFO")

    if has_cov and cov_json.exists():
        data = json.loads(cov_json.read_text())
        pct = data["totals"]["percent_covered"]
        status = "PASS" if pct >= 85 else "WARN"
        add(
            "tests",
            "line coverage %",
            f"{pct:.1f}",
            ">= 85 (CI gate)",
            status,
            "" if status == "PASS" else "CI gate assumes the tshark tests run; locally they skip",
        )
        weakest = sorted(
            (
                (v["summary"]["percent_covered"], k)
                for k, v in data["files"].items()
                if v["summary"]["num_statements"] > 100
            )
        )[:3]
        add("tests", "least-covered modules", "; ".join(f"{Path(k).name} {p:.0f}%" for p, k in weakest), "-", "INFO")
    else:
        add("tests", "line coverage %", "n/a", ">= 85", "SKIP", "pip install pytest-cov")


# --------------------------------------------------------------------------
# Code quality
# --------------------------------------------------------------------------


@guarded
def check_lint():
    if not module_available("ruff"):
        add("quality", "ruff check", "n/a", "clean", "SKIP", "pip install ruff")
        return
    code, out = run([sys.executable, "-m", "ruff", "check", "."])
    rules = sorted(set(re.findall(r"^([A-Z]+\d+) ", out, re.M)))
    add(
        "quality",
        "ruff check",
        "clean" if code == 0 else f"violations: {', '.join(rules) or 'see `ruff check .`'}",
        "clean",
        "PASS" if code == 0 else "FAIL",
    )
    _, out = run([sys.executable, "-m", "ruff", "format", "--check", "."])
    match = re.search(r"(\d+) files? would be reformatted", out)
    count = int(match.group(1)) if match else 0
    add(
        "quality",
        "files failing `ruff format`",
        count,
        "0",
        "PASS" if count == 0 else "WARN",
        "formatting is not enforced in CI",
    )


@guarded
def check_typing():
    functions = returns = args = args_annotated = 0
    for path in PKG.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions += 1
                returns += node.returns is not None
                for arg in node.args.args + node.args.kwonlyargs:
                    if arg.arg in ("self", "cls"):
                        continue
                    args += 1
                    args_annotated += arg.annotation is not None
    ret_pct = 100 * returns / functions
    arg_pct = 100 * args_annotated / args
    add(
        "quality",
        "functions with return annotation %",
        f"{ret_pct:.0f} ({returns}/{functions})",
        ">= 80",
        "PASS" if ret_pct >= 80 else "WARN",
    )
    add(
        "quality",
        "arguments annotated %",
        f"{arg_pct:.0f} ({args_annotated}/{args})",
        ">= 80",
        "PASS" if arg_pct >= 80 else "WARN",
    )
    add(
        "quality",
        "py.typed marker present",
        (PKG / "py.typed").exists(),
        "True",
        "PASS" if (PKG / "py.typed").exists() else "WARN",
    )

    if module_available("mypy"):
        _, out = run([sys.executable, "-m", "mypy", "netforensicai", "--ignore-missing-imports"])
        match = re.search(r"Found (\d+) errors?", out)
        errors = int(match.group(1)) if match else 0
        add(
            "quality",
            "mypy errors",
            errors,
            "0",
            "PASS" if errors == 0 else "WARN",
            "weak signal while few functions are annotated",
        )
    else:
        add("quality", "mypy errors", "n/a", "0", "SKIP", "pip install mypy")


@guarded
def check_module_size():
    sizes = sorted(
        ((len(p.read_text(encoding="utf-8").splitlines()), p.relative_to(ROOT)) for p in PKG.rglob("*.py")),
        reverse=True,
    )
    big = [f"{p} ({n})" for n, p in sizes if n > 1000]
    add("quality", "modules over 1000 lines", len(big), "0", "PASS" if not big else "WARN", "; ".join(big))


# --------------------------------------------------------------------------
# Security
# --------------------------------------------------------------------------

GAP_LABELS = {
    "test_audit_tail_truncation_is_detected": ("Custody log: deleting newest entry is detected", "integrity"),
    "test_expected_head_catches_truncation_even_when_the_head_file_is_rewritten": (
        "Custody log: externally noted head hash (--expect-head) catches truncation",
        "integrity",
    ),
    "test_evidence_verify_catches_modified_evidence": (
        "CLI `evidence verify` catches modified evidence",
        "integrity",
    ),
    "test_analyze_refuses_modified_evidence_and_exits_nonzero": (
        "`analyze` refuses evidence modified after ingest (exit 2)",
        "integrity",
    ),
    "test_web_throttles_repeated_failed_auth": ("Web: failed token guesses are throttled", "web"),
    "test_web_ui_sends_security_headers": ("Web: UI sends CSP / frame / nosniff headers", "web"),
    "test_web_does_not_accept_the_token_in_the_query_string": ("Web: token not accepted in URL query", "web"),
}


@guarded
def check_known_gaps():
    """Each claim is a test: gaps still open live in tests/test_proof_gaps.py,
    fixed ones in tests/test_integrity.py. --runxfail makes the expected
    failures real so a PASS here means the behaviour exists."""
    _, out = run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/test_proof_gaps.py",
            "tests/test_integrity.py",
            "--runxfail",
            "-rA",
            "-q",
            "-p",
            "no:cacheprovider",
            "--tb=no",
        ],
        timeout=300,
    )
    pattern = r"^(PASSED|FAILED) tests/test_(?:proof_gaps|integrity)\.py::(\w+)"
    seen = {name: state for state, name in re.findall(pattern, out, re.M)}
    for test, (label, area) in GAP_LABELS.items():
        state = seen.get(test)
        if state is None:
            add(f"security/{area}", label, "not run", "pass", "FAIL", "test missing or errored")
        else:
            add(
                f"security/{area}",
                label,
                "yes" if state == "PASSED" else "no",
                "yes",
                "PASS" if state == "PASSED" else "FAIL",
            )


@guarded
def check_static_security():
    if not module_available("bandit"):
        add("security/static", "bandit findings", "n/a", "0 high", "SKIP", "pip install bandit")
        return
    _, out = run([sys.executable, "-m", "bandit", "-r", "netforensicai", "-q", "-f", "json"])
    data = json.loads(out[out.index("{") :])
    by_sev = {}
    for item in data["results"]:
        by_sev[item["issue_severity"]] = by_sev.get(item["issue_severity"], 0) + 1
    high = by_sev.get("HIGH", 0)
    add("security/static", "bandit HIGH findings", high, "0", "PASS" if high == 0 else "FAIL")
    add(
        "security/static",
        "bandit MEDIUM findings",
        by_sev.get("MEDIUM", 0),
        "0",
        "INFO",
        "reviewed manually: the SQL ones interpolate constant column names only, values are parameterised",
    )


@guarded
def check_adversarial_inputs():
    """Malformed and hostile evidence must neither crash analysis nor inject markup into the HTML report."""
    import logging

    from typer.testing import CliRunner

    from netforensicai.cli import app

    logging.disable(logging.CRITICAL)  # the tool logs every step; the scorecard prints its own table
    runner = CliRunner()
    tmp = Path(tempfile.mkdtemp())
    cases = tmp / "cases"
    ev = tmp / "ev"
    ev.mkdir()
    (ev / "empty.pcap").write_bytes(b"")
    (ev / "garbage.pcap").write_bytes(bytes(range(256)) * 20)
    (ev / "broken.json").write_text('{"events": [ {"a":1}, ')
    (ev / "deep.json").write_text("[" * 50000 + "]" * 50000)
    (ev / "bad.csv").write_text('timestamp,src_ip\n"unterminated,1.2.3.4\n\x00\x00\n')
    (ev / "fake.evtx").write_bytes(b"ElfFile\x00" + b"\x00" * 4000)
    (ev / "hostile.json").write_text(
        json.dumps(
            [
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "event_type": "process_creation",
                    "host": "<img src=x onerror=alert(1)>",
                    "process_name": "</script><script>alert('xss')</script>",
                    "domain": 'evil.top"><svg/onload=alert(2)>',
                },
            ]
        )
    )

    result = runner.invoke(app, ["case", "create", "--name", "adv", "--cases-dir", str(cases)])
    assert result.exit_code == 0, result.output
    for path in sorted(ev.iterdir()):
        added = runner.invoke(app, ["evidence", "add", str(path), "--case", "INC-0001", "--cases-dir", str(cases)])
        assert added.exit_code == 0, f"{path.name}: {added.output}"

    analyzed = runner.invoke(app, ["analyze", "--case", "INC-0001", "--cases-dir", str(cases)])
    crashed = analyzed.exception is not None and not isinstance(analyzed.exception, SystemExit)
    ok = analyzed.exit_code == 0 and not crashed and "Traceback" not in analyzed.output
    add(
        "robustness",
        "analyze survives 7 malformed/hostile inputs",
        "yes" if ok else "no",
        "yes",
        "PASS" if ok else "FAIL",
        "" if ok else analyzed.output[-300:],
    )

    report = cases / "INC-0001" / "reports" / "report.html"
    runner.invoke(app, ["report", "generate", "--case", "INC-0001", "--format", "html", "--cases-dir", str(cases)])
    html = report.read_text(encoding="utf-8") if report.exists() else ""
    injected = re.search(r"<(img|svg)[^>]*(onerror|onload)=|<script>alert", html, re.I)
    add(
        "robustness",
        "HTML report escapes attacker-controlled evidence",
        "no raw tags" if html and not injected else "INJECTED",
        "no raw tags",
        "PASS" if html and not injected else "FAIL",
    )


# --------------------------------------------------------------------------
# Performance (opt-in)
# --------------------------------------------------------------------------


@guarded
def check_benchmark():
    code, out = run([sys.executable, "samples/benchmark.py", "--scale", "20"], timeout=900)
    rows = re.findall(r"^\s*([\d,]+)\s+([\d.]+)\s+([\d,]+)\s+([\d.]+)\s+([\d,]+)\s+([\d.]+)\s+(\d+)\s*$", out, re.M)
    if code != 0 or not rows:
        add("performance", "scapy-engine throughput", "n/a", "-", "FAIL", out[-200:])
        return
    packets, mb, _events, sec, pps, mbmin, peak = rows[-1]
    add("performance", "scapy-engine throughput (pkt/s)", pps, "-", "INFO", f"{packets} packets, {mb} MB in {sec}s")
    add("performance", "scapy-engine throughput (MB/min)", mbmin, "-", "INFO")
    add("performance", "peak memory (MB)", peak, "-", "INFO")
    if "link budget" in out:
        add(
            "performance",
            "correlation hit its 50,000-link cap",
            "yes",
            "no",
            "WARN",
            "later events were not correlated at this scale",
        )


# --------------------------------------------------------------------------


def render(env):
    width = max(len(r["check"]) for r in RESULTS)
    print(
        f"\nNetForensicAI scorecard  |  {env['git']}  |  Python {env['python']}  |  tshark: {'yes' if env['tshark_installed'] else 'no'}\n"
    )
    category = None
    for row in RESULTS:
        if row["category"] != category:
            category = row["category"]
            print(f"\n[{category}]")
        line = f"  {row['status']:<4}  {row['check']:<{width}}  {row['value']}"
        if row["target"] not in ("-", ""):
            line += f"   (target: {row['target']})"
        print(line)
        if row["note"] and row["status"] != "PASS":
            print(f"        note: {row['note']}")
    counts = {s: sum(r["status"] == s for r in RESULTS) for s in ("PASS", "WARN", "FAIL", "INFO", "SKIP")}
    print("\n" + "  ".join(f"{k}={v}" for k, v in counts.items()) + "\n")
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--fast", action="store_true", help="skip the full test suite and coverage")
    parser.add_argument("--bench", action="store_true", help="add the throughput benchmark (slow)")
    parser.add_argument("--json", metavar="PATH", help="also write results as JSON")
    parser.add_argument("--strict", action="store_true", help="exit 1 if any check FAILs")
    args = parser.parse_args()

    env = environment()
    if not args.fast:
        check_tests(env)
    check_lint()
    check_typing()
    check_module_size()
    check_static_security()
    check_known_gaps()
    check_adversarial_inputs()
    if args.bench:
        check_benchmark()

    counts = render(env)
    if args.json:
        Path(args.json).write_text(json.dumps({"environment": env, "summary": counts, "results": RESULTS}, indent=2))
    return 1 if args.strict and counts["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
