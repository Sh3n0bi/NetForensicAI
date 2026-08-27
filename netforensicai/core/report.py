"""Case report generation.

Assembles case data (case info, evidence + integrity, entities, timeline,
artifacts, network indicators, findings, ATT&CK mappings, notes) into one
report structure, then renders it as Markdown, JSON, or HTML.

A section with nothing behind it yet (no threat intel checked, no ATT&CK
techniques detected) says so plainly rather than being silently omitted -
the report should never imply more analysis happened than actually did.
Nothing here triggers new analysis as a side effect of generating a
report: threat intelligence lookups are explicit, opt-in actions
(`netforensic investigate --vt-api`) and ATT&CK mapping is its own
explicit action (`netforensic attack scan`) - this module only ever reads
what's already been recorded in the case.
"""

import html
import json
import logging
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from netforensicai.core.evidence import EvidenceError, EvidenceManager
from netforensicai.core.finding import FindingManager
from netforensicai.core.store import CaseStore
from netforensicai.core.timeline import build_timeline

logger = logging.getLogger(__name__)

MARKDOWN_TIMELINE_LIMIT = 200

LIMITATIONS = [
    "This report is generated entirely by deterministic parsing, normalization, and correlation - "
    "no AI-driven interpretation has been applied to any finding or lead in this document.",
    "Correlation (\"related\" / \"possible_relationship\") reflects shared entities and/or time "
    "proximity only. It is not evidence of causality - two events being linked here does not mean "
    "one caused, followed from, or is otherwise definitively connected to the other.",
    "ATT&CK technique mappings are deterministic rule matches over already-normalized events "
    "(see `netforensic attack scan`), not an AI or automated claim that a technique definitely "
    "occurred - each one is a 'potential' suggestion until an investigator explicitly confirms it.",
    "Bundled detections (core/detections.py) are local, deterministic pattern matches over "
    "already-normalized events - not AI-driven, not an external lookup, and not a claim that "
    "something malicious happened. They are recomputed on every `netforensic analyze` run and, "
    "unlike ATT&CK mappings, carry no investigator-settable status - there is nothing to confirm "
    "or reject, only evidence worth reviewing.",
    "Threat intelligence lookups (e.g. VirusTotal) are explicit, opt-in actions performed via "
    "`netforensic investigate --vt-api` and are not automatically run or persisted during report "
    "generation; this report reflects only what has already been recorded in the case.",
    "Entity extraction, correlation, bundled detections, and ATT&CK mapping only cover the event "
    "types and fields the current parsers populate and the current rule sets check for - they are "
    "not exhaustive.",
]

NETWORK_INDICATOR_TYPES = ("ip_address", "domain", "url", "port")


def build_report(case, case_dir):
    """Assemble the full report data structure for `case`. Pure read - never
    modifies the case, and never makes an external network call."""
    case_dir = Path(case_dir)
    evidence_manager = EvidenceManager(case_dir)
    finding_manager = FindingManager(case_dir)

    evidence_sources = []
    for evidence in evidence_manager.list():
        try:
            integrity_status = "verified" if evidence_manager.verify(evidence.evidence_id) else "MISMATCH - possible tampering"
        except EvidenceError as e:
            integrity_status = f"could not verify: {e}"
        evidence_sources.append(
            {
                "evidence_id": evidence.evidence_id,
                "filename": evidence.filename,
                "evidence_type": evidence.evidence_type,
                "sha256": evidence.sha256,
                "size_bytes": evidence.size_bytes,
                "imported_at": evidence.imported_at,
                "source_path": evidence.source_path,
                "integrity_status": integrity_status,
            }
        )

    with CaseStore(case_dir) as store:
        all_events = store.all_events()
        entities = store.list_entities()
        correlation_links = store.list_correlation_links()
        timeline_entries = [entry.to_dict() for entry in build_timeline(store)]
        threat_intel_results = store.list_threat_intel()
        attack_techniques = store.list_techniques()
        detections = store.list_detections()

        entity_event_counts = Counter()
        for links in store.entity_ids_by_event().values():
            for entity_id, _entity_type, _value, _field in links:
                entity_event_counts[entity_id] += 1

    affected_entities = [
        {**entity, "event_count": entity_event_counts.get(entity["entity_id"], 0)} for entity in entities
    ]
    network_indicators = [e for e in affected_entities if e["entity_type"] in NETWORK_INDICATOR_TYPES]

    findings = finding_manager.list()
    investigation_findings = [
        {
            "finding_id": f.finding_id,
            "title": f.title,
            "status": f.status,
            "severity": f.severity,
            "assessment": f.assessment,
            "evidence_refs": f.evidence_refs,
            "investigator_notes": f.investigator_notes,
            "created_by": f.created_by,
            "created_at": f.created_at,
            "updated_at": f.updated_at,
        }
        for f in findings
    ]

    findings_by_status = Counter(f.status for f in findings)
    related_count = sum(1 for link in correlation_links if link["relationship_type"] == "related")
    possible_count = sum(1 for link in correlation_links if link["relationship_type"] == "possible_relationship")

    status_breakdown = ", ".join(f"{count} {status}" for status, count in findings_by_status.items())
    executive_summary = (
        f"This case includes {len(evidence_sources)} evidence item(s), {len(all_events)} normalized "
        f"event(s), and {len(entities)} distinct entit{'y' if len(entities) == 1 else 'ies'}. "
        f"Correlation identified {related_count} related event pair(s) and {possible_count} "
        f"possible_relationship (time-proximity-only) pair(s). {len(detections)} bundled detection "
        f"rule match(es) were found. {len(findings)} finding(s) have been recorded"
        + (f" ({status_breakdown})." if findings else ".")
    )

    threat_intel_results = [
        {**row, "checked_at": row["checked_at"].isoformat() if row["checked_at"] else None}
        for row in threat_intel_results
    ]
    threat_intelligence_note = (
        "Threat intelligence lookups are explicit and opt-in (see `netforensic investigate --vt-api`) "
        "and are only ever checked when an investigator runs that command; results below are cached "
        "from those runs, not gathered automatically for this report."
        if threat_intel_results
        else (
            "Threat intelligence lookups are explicit and opt-in (see `netforensic investigate "
            "--vt-api`) and are not automatically run; no results have been recorded for this case."
        )
    )

    attack_techniques = [
        {
            **t,
            "created_at": t["created_at"].isoformat() if t["created_at"] else None,
            "updated_at": t["updated_at"].isoformat() if t["updated_at"] else None,
        }
        for t in attack_techniques
    ]
    attack_mapping_note = (
        "Deterministic rule-based suggestions only (see `netforensic attack scan`), never an automated "
        "claim that a technique occurred - each one cites the specific events it's based on and carries "
        "a status the investigator sets explicitly (potential/confirmed/rejected)."
        if attack_techniques
        else (
            "No potential ATT&CK techniques detected. Techniques are only ever suggested by deterministic "
            "rules over already-normalized events (see `netforensic attack scan`) - never inferred "
            "automatically for this report."
        )
    )

    detections = [{**d, "detected_at": d["detected_at"].isoformat() if d["detected_at"] else None} for d in detections]
    detections_note = (
        "Local, deterministic pattern matches (see core/detections.py) - no AI, no external network "
        "call, recomputed automatically every `netforensic analyze` run. A flag pointing at evidence "
        "worth a look, never a claim that something malicious happened."
        if detections
        else (
            "No bundled detection rules matched. These are local, deterministic pattern matches - no "
            "AI, no external network call - recomputed automatically every `netforensic analyze` run."
        )
    )

    return {
        "case": {
            "case_id": case.case_id,
            "name": case.name,
            "description": case.description,
            "investigator": case.investigator,
            "status": case.status,
            "created_at": case.created_at,
            "updated_at": case.updated_at,
        },
        "executive_summary": executive_summary,
        "evidence_sources": evidence_sources,
        "affected_entities": affected_entities,
        "timeline": timeline_entries,
        "artifacts": list(case.artifacts),
        "network_indicators": network_indicators,
        "threat_intelligence_note": threat_intelligence_note,
        "threat_intelligence_results": threat_intel_results,
        "investigation_findings": investigation_findings,
        "detections_note": detections_note,
        "detections": detections,
        "attack_mapping_note": attack_mapping_note,
        "attack_techniques": attack_techniques,
        "investigator_notes": list(case.notes),
        "limitations": LIMITATIONS,
        "recommendations": _generate_recommendations(findings, findings_by_status),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _generate_recommendations(findings, findings_by_status):
    recommendations = []
    open_count = findings_by_status.get("Open", 0) + findings_by_status.get("Investigating", 0)
    if open_count:
        recommendations.append(
            f"{open_count} finding(s) remain Open or Investigating - review and either confirm, "
            "reject, or mark as a false positive."
        )
    if not findings:
        recommendations.append(
            "No findings have been recorded for this case yet. Use `netforensic investigate` on "
            "entities of interest surfaced during analysis, and `netforensic finding create` to "
            "record any conclusions."
        )
    if not recommendations:
        recommendations.append("No outstanding automated recommendations for this case.")
    return recommendations


def render_json(report):
    return json.dumps(report, indent=2)


def _ti_result_text(result):
    if result.get("error"):
        return f"error: {result['error']}"
    verdict = "YES" if result["malicious"] else "no"
    return f"{verdict} ({result['malicious_count']}/{result['total_engines']})"


def render_markdown(report):
    case = report["case"]
    lines = [
        f"# Case Report: {case['case_id']} - {case['name']}",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "## Case Information",
        f"- **Case ID:** {case['case_id']}",
        f"- **Name:** {case['name']}",
        f"- **Description:** {case['description'] or '(none)'}",
        f"- **Investigator:** {case['investigator']}",
        f"- **Status:** {case['status']}",
        f"- **Created:** {case['created_at']}",
        f"- **Updated:** {case['updated_at']}",
        "",
        "## Executive Summary",
        report["executive_summary"],
        "",
        "## Evidence Sources",
    ]

    if report["evidence_sources"]:
        lines += ["| Evidence ID | Filename | Type | Size (bytes) | Imported |", "|---|---|---|---|---|"]
        lines += [
            f"| {e['evidence_id']} | {e['filename']} | {e['evidence_type']} | {e['size_bytes']} | {e['imported_at']} |"
            for e in report["evidence_sources"]
        ]
    else:
        lines.append("No evidence recorded.")

    lines += ["", "## Evidence Integrity"]
    if report["evidence_sources"]:
        lines += ["| Evidence ID | SHA-256 | Status |", "|---|---|---|"]
        lines += [
            f"| {e['evidence_id']} | `{e['sha256']}` | {e['integrity_status']} |" for e in report["evidence_sources"]
        ]
    else:
        lines.append("No evidence recorded.")

    lines += ["", "## Affected Entities"]
    if report["affected_entities"]:
        lines += ["| Type | Value | Event Count |", "|---|---|---|"]
        lines += [f"| {e['entity_type']} | {e['value']} | {e['event_count']} |" for e in report["affected_entities"]]
    else:
        lines.append("No entities extracted.")

    lines += ["", "## Timeline"]
    timeline = report["timeline"]
    shown = timeline[:MARKDOWN_TIMELINE_LIMIT]
    if shown:
        lines += ["| Timestamp | Type | Source | Evidence | Confidence |", "|---|---|---|---|---|"]
        lines += [
            f"| {e['timestamp'] or 'unknown'} | {e['event_type']} | {e['source']} | {e['evidence_id']} | {e['confidence']} |"
            for e in shown
        ]
        if len(timeline) > MARKDOWN_TIMELINE_LIMIT:
            lines += [
                "",
                f"_...{len(timeline) - MARKDOWN_TIMELINE_LIMIT} more entries omitted; see "
                "`netforensic timeline show` or the JSON report for the full timeline._",
            ]
    else:
        lines.append("No timeline entries.")

    lines += ["", "## Artifacts"]
    if report["artifacts"]:
        lines += [f"- `{path}`" for path in report["artifacts"]]
    else:
        lines.append("No artifacts extracted.")

    lines += ["", "## Network Indicators"]
    if report["network_indicators"]:
        lines += ["| Type | Value |", "|---|---|"]
        lines += [f"| {e['entity_type']} | {e['value']} |" for e in report["network_indicators"]]
    else:
        lines.append("No network indicators observed.")

    lines += ["", "## Threat Intelligence", report["threat_intelligence_note"]]
    if report["threat_intelligence_results"]:
        lines += ["", "| Entity Type | Value | Provider | Checked | Result |", "|---|---|---|---|---|"]
        lines += [
            f"| {r['entity_type']} | {r['value']} | {r['provider']} | {r['checked_at']} | {_ti_result_text(r)} |"
            for r in report["threat_intelligence_results"]
        ]

    lines += ["", "## Investigation Findings"]
    if report["investigation_findings"]:
        for f in report["investigation_findings"]:
            lines += [
                f"### {f['finding_id']}: {f['title']}",
                f"- **Status:** {f['status']}",
                f"- **Severity:** {f['severity']}",
                f"- **Assessment:** {f['assessment'] or '(none)'}",
            ]
            if f["evidence_refs"]:
                lines.append(f"- **Evidence:** {', '.join(r['event_id'] for r in f['evidence_refs'])}")
            if f["investigator_notes"]:
                lines.append("- **Notes:**")
                lines += [f"  - {n['timestamp']} ({n['author']}): {n['text']}" for n in f["investigator_notes"]]
            lines.append("")
    else:
        lines += ["No findings recorded.", ""]

    lines += ["## Bundled Detections", report["detections_note"]]
    if report["detections"]:
        lines += ["", "| Severity | Rule | Event | Description |", "|---|---|---|---|"]
        lines += [
            f"| {d['severity']} | {d['rule_name']} | {d['evidence_id']}/{d['event_id']} | {d['description']} |"
            for d in report["detections"]
        ]
    lines.append("")

    lines += ["## Potential ATT&CK Mapping", report["attack_mapping_note"]]
    if report["attack_techniques"]:
        lines += ["", "| Technique | Name | Confidence | Status | Events |", "|---|---|---|---|---|"]
        lines += [
            f"| {t['technique_id']} | {t['technique_name']} | {t['confidence']} | {t['status']} | {t['event_count']} |"
            for t in report["attack_techniques"]
        ]
    lines.append("")

    lines += ["## Investigator Notes"]
    if report["investigator_notes"]:
        lines += [f"- {note}" for note in report["investigator_notes"]]
    else:
        lines.append("No case-level notes recorded. See per-finding notes above.")

    lines += ["", "## Limitations"]
    lines += [f"- {item}" for item in report["limitations"]]

    lines += ["", "## Recommendations"]
    lines += [f"- {item}" for item in report["recommendations"]]
    lines.append("")

    return "\n".join(lines)


def _e(value):
    """HTML-escape a value that may have come from user-supplied case/
    evidence/finding text (names, titles, notes, filenames)."""
    return html.escape(str(value)) if value is not None else ""


def render_html(report):
    case = report["case"]
    parts = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        f"<title>Case Report: {_e(case['case_id'])}</title>",
        "<style>",
        "body{font-family:sans-serif;max-width:900px;margin:2em auto;padding:0 1em;color:#1a1a1a;}",
        "table{border-collapse:collapse;width:100%;margin:0.5em 0;}",
        "th,td{border:1px solid #ccc;padding:4px 8px;text-align:left;font-size:0.9em;}",
        "th{background:#f0f0f0;}",
        "code{background:#f5f5f5;padding:1px 4px;}",
        "h2{border-bottom:1px solid #ccc;padding-bottom:0.2em;margin-top:2em;}",
        "</style></head><body>",
        f"<h1>Case Report: {_e(case['case_id'])} - {_e(case['name'])}</h1>",
        f"<p>Generated: {_e(report['generated_at'])}</p>",
        "<h2>Case Information</h2><ul>",
        f"<li><b>Case ID:</b> {_e(case['case_id'])}</li>",
        f"<li><b>Name:</b> {_e(case['name'])}</li>",
        f"<li><b>Description:</b> {_e(case['description']) or '(none)'}</li>",
        f"<li><b>Investigator:</b> {_e(case['investigator'])}</li>",
        f"<li><b>Status:</b> {_e(case['status'])}</li>",
        f"<li><b>Created:</b> {_e(case['created_at'])}</li>",
        f"<li><b>Updated:</b> {_e(case['updated_at'])}</li>",
        "</ul>",
        "<h2>Executive Summary</h2>",
        f"<p>{_e(report['executive_summary'])}</p>",
        "<h2>Evidence Sources</h2>",
    ]

    if report["evidence_sources"]:
        parts.append("<table><tr><th>Evidence ID</th><th>Filename</th><th>Type</th><th>Size</th><th>Imported</th></tr>")
        for e in report["evidence_sources"]:
            parts.append(
                f"<tr><td>{_e(e['evidence_id'])}</td><td>{_e(e['filename'])}</td><td>{_e(e['evidence_type'])}</td>"
                f"<td>{e['size_bytes']}</td><td>{_e(e['imported_at'])}</td></tr>"
            )
        parts.append("</table>")
    else:
        parts.append("<p>No evidence recorded.</p>")

    parts.append("<h2>Evidence Integrity</h2>")
    if report["evidence_sources"]:
        parts.append("<table><tr><th>Evidence ID</th><th>SHA-256</th><th>Status</th></tr>")
        for e in report["evidence_sources"]:
            parts.append(
                f"<tr><td>{_e(e['evidence_id'])}</td><td><code>{_e(e['sha256'])}</code></td>"
                f"<td>{_e(e['integrity_status'])}</td></tr>"
            )
        parts.append("</table>")
    else:
        parts.append("<p>No evidence recorded.</p>")

    parts.append("<h2>Affected Entities</h2>")
    if report["affected_entities"]:
        parts.append("<table><tr><th>Type</th><th>Value</th><th>Event Count</th></tr>")
        for e in report["affected_entities"]:
            parts.append(f"<tr><td>{_e(e['entity_type'])}</td><td>{_e(e['value'])}</td><td>{e['event_count']}</td></tr>")
        parts.append("</table>")
    else:
        parts.append("<p>No entities extracted.</p>")

    parts.append("<h2>Timeline</h2>")
    timeline = report["timeline"]
    shown = timeline[:MARKDOWN_TIMELINE_LIMIT]
    if shown:
        parts.append("<table><tr><th>Timestamp</th><th>Type</th><th>Source</th><th>Evidence</th><th>Confidence</th></tr>")
        for e in shown:
            parts.append(
                f"<tr><td>{_e(e['timestamp'] or 'unknown')}</td><td>{_e(e['event_type'])}</td>"
                f"<td>{_e(e['source'])}</td><td>{_e(e['evidence_id'])}</td><td>{_e(e['confidence'])}</td></tr>"
            )
        parts.append("</table>")
        if len(timeline) > MARKDOWN_TIMELINE_LIMIT:
            parts.append(
                f"<p><i>...{len(timeline) - MARKDOWN_TIMELINE_LIMIT} more entries omitted; see the JSON "
                "report for the full timeline.</i></p>"
            )
    else:
        parts.append("<p>No timeline entries.</p>")

    parts.append("<h2>Artifacts</h2>")
    if report["artifacts"]:
        parts.append("<ul>" + "".join(f"<li><code>{_e(p)}</code></li>" for p in report["artifacts"]) + "</ul>")
    else:
        parts.append("<p>No artifacts extracted.</p>")

    parts.append("<h2>Network Indicators</h2>")
    if report["network_indicators"]:
        parts.append("<table><tr><th>Type</th><th>Value</th></tr>")
        for e in report["network_indicators"]:
            parts.append(f"<tr><td>{_e(e['entity_type'])}</td><td>{_e(e['value'])}</td></tr>")
        parts.append("</table>")
    else:
        parts.append("<p>No network indicators observed.</p>")

    parts.append(f"<h2>Threat Intelligence</h2><p>{_e(report['threat_intelligence_note'])}</p>")
    if report["threat_intelligence_results"]:
        parts.append("<table><tr><th>Entity Type</th><th>Value</th><th>Provider</th><th>Checked</th><th>Result</th></tr>")
        for r in report["threat_intelligence_results"]:
            parts.append(
                f"<tr><td>{_e(r['entity_type'])}</td><td>{_e(r['value'])}</td><td>{_e(r['provider'])}</td>"
                f"<td>{_e(r['checked_at'])}</td><td>{_e(_ti_result_text(r))}</td></tr>"
            )
        parts.append("</table>")

    parts.append("<h2>Investigation Findings</h2>")
    if report["investigation_findings"]:
        for f in report["investigation_findings"]:
            parts.append(f"<h3>{_e(f['finding_id'])}: {_e(f['title'])}</h3><ul>")
            parts.append(f"<li><b>Status:</b> {_e(f['status'])}</li>")
            parts.append(f"<li><b>Severity:</b> {_e(f['severity'])}</li>")
            parts.append(f"<li><b>Assessment:</b> {_e(f['assessment']) or '(none)'}</li>")
            if f["evidence_refs"]:
                parts.append(f"<li><b>Evidence:</b> {_e(', '.join(r['event_id'] for r in f['evidence_refs']))}</li>")
            parts.append("</ul>")
            if f["investigator_notes"]:
                parts.append("<ul>")
                for n in f["investigator_notes"]:
                    parts.append(f"<li>{_e(n['timestamp'])} ({_e(n['author'])}): {_e(n['text'])}</li>")
                parts.append("</ul>")
    else:
        parts.append("<p>No findings recorded.</p>")

    parts.append(f"<h2>Bundled Detections</h2><p>{_e(report['detections_note'])}</p>")
    if report["detections"]:
        parts.append("<table><tr><th>Severity</th><th>Rule</th><th>Event</th><th>Description</th></tr>")
        for d in report["detections"]:
            parts.append(
                f"<tr><td>{_e(d['severity'])}</td><td>{_e(d['rule_name'])}</td>"
                f"<td>{_e(d['evidence_id'])}/{_e(d['event_id'])}</td><td>{_e(d['description'])}</td></tr>"
            )
        parts.append("</table>")

    parts.append(f"<h2>Potential ATT&amp;CK Mapping</h2><p>{_e(report['attack_mapping_note'])}</p>")
    if report["attack_techniques"]:
        parts.append("<table><tr><th>Technique</th><th>Name</th><th>Confidence</th><th>Status</th><th>Events</th></tr>")
        for t in report["attack_techniques"]:
            parts.append(
                f"<tr><td>{_e(t['technique_id'])}</td><td>{_e(t['technique_name'])}</td>"
                f"<td>{_e(t['confidence'])}</td><td>{_e(t['status'])}</td><td>{t['event_count']}</td></tr>"
            )
        parts.append("</table>")

    parts.append("<h2>Investigator Notes</h2>")
    if report["investigator_notes"]:
        parts.append("<ul>" + "".join(f"<li>{_e(n)}</li>" for n in report["investigator_notes"]) + "</ul>")
    else:
        parts.append("<p>No case-level notes recorded. See per-finding notes above.</p>")

    parts.append("<h2>Limitations</h2><ul>" + "".join(f"<li>{_e(item)}</li>" for item in report["limitations"]) + "</ul>")
    parts.append(
        "<h2>Recommendations</h2><ul>" + "".join(f"<li>{_e(item)}</li>" for item in report["recommendations"]) + "</ul>"
    )
    parts.append("</body></html>")

    return "\n".join(parts)


RENDERERS = {
    "markdown": render_markdown,
    "json": render_json,
    "html": render_html,
}

EXTENSION_BY_FORMAT = {
    "markdown": "md",
    "json": "json",
    "html": "html",
}
