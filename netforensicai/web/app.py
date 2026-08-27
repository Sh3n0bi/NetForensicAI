"""Local, read-only web UI for browsing cases: evidence, timeline, entity
graph, findings, and reports - a thin visualization layer over the same
core modules the CLI uses, not a second implementation of any of it.

Local-first and single-user by design: binds to 127.0.0.1 by default,
has no authentication, and Flask's debug/reloader mode is never enabled
here (it exposes an interactive in-browser debugger capable of arbitrary
code execution - a serious risk if this process were ever reachable from
a network). Only pass a different --host if you understand and accept
exposing this to other machines.

Write surface is intentionally minimal: browsing case data never mutates
it. The two POST endpoints (threat-intel check, AI hypothesis) trigger
optional, explicit external lookups - the same actions
`netforensic investigate --vt-api` / `--ai` already perform - not writes
to the case's own findings/evidence data. Creating or updating a Finding
remains a CLI-only action in this version.

Every request opens and closes its own short-lived CaseStore (DuckDB
connection) rather than sharing one across requests - see cli.py's `web`
command for why the server also runs single-threaded.
"""

import logging
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from netforensicai.core.case import CaseError, CaseManager
from netforensicai.core.evidence import EvidenceManager
from netforensicai.core.event import parse_timestamp
from netforensicai.core.finding import FindingManager
from netforensicai.core.investigate import investigate_entity
from netforensicai.core.report import RENDERERS, build_report
from netforensicai.core.store import CaseStore
from netforensicai.core.timeline import build_timeline, filter_timeline

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static"

REPORT_MIMETYPES = {"markdown": "text/markdown", "json": "application/json", "html": "text/html"}


class ApiError(Exception):
    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def create_app(cases_dir="cases"):
    app = Flask(__name__, static_folder=None)
    case_manager = CaseManager(cases_dir)

    def _load_case(case_id):
        try:
            return case_manager.load(case_id)
        except CaseError as e:
            raise ApiError(str(e), 404)

    def _case_dir(case):
        return Path(cases_dir) / case.case_id

    @app.errorhandler(ApiError)
    def handle_api_error(err):
        return jsonify({"error": err.message}), err.status_code

    # --- static frontend ---

    @app.route("/")
    def index():
        return send_from_directory(STATIC_DIR, "index.html")

    @app.route("/<path:filename>")
    def static_files(filename):
        return send_from_directory(STATIC_DIR, filename)

    # --- cases ---

    @app.route("/api/cases")
    def list_cases():
        return jsonify([c.to_dict() for c in case_manager.list()])

    @app.route("/api/cases/<case_id>")
    def get_case(case_id):
        case = _load_case(case_id)
        evidence_items = EvidenceManager(_case_dir(case)).list()
        with CaseStore(_case_dir(case)) as store:
            event_count = store.count_events()
            entity_count = store.count_entities()
        finding_count = len(FindingManager(_case_dir(case)).list())

        data = case.to_dict()
        data.update(
            evidence_count=len(evidence_items),
            event_count=event_count,
            entity_count=entity_count,
            finding_count=finding_count,
        )
        return jsonify(data)

    # --- evidence ---

    @app.route("/api/cases/<case_id>/evidence")
    def list_evidence(case_id):
        case = _load_case(case_id)
        items = EvidenceManager(_case_dir(case)).list()
        return jsonify([e.to_dict() for e in items])

    # --- timeline ---

    @app.route("/api/cases/<case_id>/timeline")
    def get_timeline(case_id):
        case = _load_case(case_id)
        with CaseStore(_case_dir(case)) as store:
            entries = build_timeline(store)

        time_from = parse_timestamp(request.args.get("from")) if request.args.get("from") else None
        time_to = parse_timestamp(request.args.get("to")) if request.args.get("to") else None
        entries = filter_timeline(
            entries,
            time_from=time_from,
            time_to=time_to,
            user=request.args.get("user"),
            ip=request.args.get("ip"),
            hostname=request.args.get("hostname"),
            process=request.args.get("process"),
            file=request.args.get("file"),
            event_type=request.args.get("type"),
            evidence_id=request.args.get("evidence"),
        )
        return jsonify([e.to_dict() for e in entries])

    # --- entities ---

    @app.route("/api/cases/<case_id>/entities")
    def list_entities(case_id):
        case = _load_case(case_id)
        entity_type = request.args.get("type") or None
        query = request.args.get("q", "").strip().lower()
        with CaseStore(_case_dir(case)) as store:
            items = store.list_entities(entity_type=entity_type)
        if query:
            items = [e for e in items if query in e["value"].lower()]
        return jsonify(items)

    @app.route("/api/cases/<case_id>/entities/<entity_id>/graph")
    def entity_graph(case_id, entity_id):
        case = _load_case(case_id)
        with CaseStore(_case_dir(case)) as store:
            entity = store.get_entity(entity_id)
            if entity is None:
                raise ApiError(f"Entity not found: {entity_id}", 404)
            related = store.related_entities(entity_id)
        return jsonify({"entity": entity, "related": related})

    # --- investigate ---

    @app.route("/api/cases/<case_id>/investigate")
    def investigate(case_id):
        case = _load_case(case_id)
        entity_type = request.args.get("type")
        value = request.args.get("value")
        if not entity_type or not value:
            raise ApiError("type and value query parameters are required")

        with CaseStore(_case_dir(case)) as store:
            result = investigate_entity(store, entity_type, value)
            if result is None:
                raise ApiError(f"No evidence of {entity_type} '{value}' found in this case", 404)
            return jsonify(
                {
                    "entity": result.entity,
                    "evidence_ids": result.evidence_ids,
                    "timeline": [e.to_dict() for e in result.timeline_entries],
                    "related_entities": result.related_entities,
                    "correlation_links": result.correlation_links,
                    "leads": result.leads,
                }
            )

    # --- threat intel (opt-in, explicit external call) ---

    @app.route("/api/cases/<case_id>/threat-intel", methods=["POST"])
    def check_threat_intel(case_id):
        case = _load_case(case_id)
        payload = request.get_json(force=True, silent=True) or {}
        entity_id = payload.get("entity_id")
        entity_type = payload.get("entity_type")
        value = payload.get("value")
        if not all([entity_id, entity_type, value]):
            raise ApiError("entity_id, entity_type, and value are required")

        from netforensicai.core import threat_intel
        from netforensicai.intel import virustotal

        resolved_key = virustotal.get_api_key(payload.get("api_key"))
        with CaseStore(_case_dir(case)) as store:
            result = threat_intel.check_entity(store, entity_id, entity_type, value, resolved_key)
        if result is None:
            raise ApiError(f"No threat intelligence source for entity type '{entity_type}'")
        return jsonify(result)

    # --- AI hypothesis (opt-in, explicit external call) ---

    @app.route("/api/cases/<case_id>/ai-hypothesis", methods=["POST"])
    def ai_hypothesis(case_id):
        case = _load_case(case_id)
        payload = request.get_json(force=True, silent=True) or {}
        entity_type = payload.get("entity_type")
        value = payload.get("value")

        if not entity_type or not value:
            raise ApiError("entity_type and value are required")

        from netforensicai.core.ai_assistant import AssistantError, generate_hypothesis

        with CaseStore(_case_dir(case)) as store:
            result = investigate_entity(store, entity_type, value)
            if result is None:
                raise ApiError(f"No evidence of {entity_type} '{value}' found in this case", 404)
            events = result.events

        try:
            hypothesis = generate_hypothesis(events, api_key=payload.get("api_key"))
        except AssistantError as e:
            raise ApiError(str(e), 502)
        return jsonify(hypothesis.model_dump())

    # --- findings (read-only) ---

    @app.route("/api/cases/<case_id>/findings")
    def list_findings(case_id):
        case = _load_case(case_id)
        findings = FindingManager(_case_dir(case)).list()
        return jsonify([f.to_dict() for f in findings])

    # --- reports ---

    @app.route("/api/cases/<case_id>/report/<fmt>")
    def get_report(case_id, fmt):
        case = _load_case(case_id)
        fmt = fmt.lower()
        if fmt not in RENDERERS:
            raise ApiError(f"Unsupported format '{fmt}'. Choose from: {', '.join(RENDERERS)}")
        report = build_report(case, _case_dir(case))
        content = RENDERERS[fmt](report)
        return app.response_class(content, mimetype=REPORT_MIMETYPES[fmt])

    return app
