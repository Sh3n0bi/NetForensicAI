"""Local web UI for browsing cases: evidence, timeline, entity graph,
findings, reports, and live capture - a thin visualization layer over the
same core modules the CLI uses, not a second implementation of any of it.

Local-first and single-user by design: binds to 127.0.0.1 by default,
has no authentication, and Flask's debug/reloader mode is never enabled
here (it exposes an interactive in-browser debugger capable of arbitrary
code execution - a serious risk if this process were ever reachable from
a network). Only pass a different --host if you understand and accept
exposing this to other machines.

Write surface is deliberately narrow. Evidence upload and analyze mirror
`netforensic evidence add` / `analyze` exactly (same EvidenceManager /
pipeline calls) - not a second ingestion path. Threat-intel check and AI
hypothesis trigger the same explicit, opt-in external lookups
`investigate --vt-api` / `--ai` already perform. Live capture start/stop
control a CaptureSession (core/capture.py) the same way `netforensic
capture` does. Creating or updating a Finding remains CLI-only.

All CaseStore access here goes through locked_store() rather than
CaseStore(...) directly: a live capture session's background ingestion
thread can be writing to a case's DuckDB file at the same moment a
browser request reads it, and DuckDB is single-writer - see
core/store.py's GLOBAL_WRITE_LOCK.
"""

import logging
import shutil
import tempfile
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.utils import secure_filename

from netforensicai.core.case import CaseError, CaseManager
from netforensicai.core.evidence import EvidenceError, EvidenceManager
from netforensicai.core.event import parse_timestamp
from netforensicai.core.finding import FindingManager
from netforensicai.core.investigate import investigate_entity
from netforensicai.core.report import RENDERERS, build_report
from netforensicai.core.store import locked_store
from netforensicai.core.timeline import build_timeline, filter_timeline

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static"

REPORT_MIMETYPES = {"markdown": "text/markdown", "json": "application/json", "html": "text/html"}

# Generous but bounded - evidence files (especially pcaps) can be large,
# but an unbounded upload is a disk-exhaustion DoS against a local tool
# with no auth in front of it.
MAX_UPLOAD_BYTES = 1024 * 1024 * 1024


class ApiError(Exception):
    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def create_app(cases_dir="cases"):
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
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

    @app.errorhandler(413)
    def handle_too_large(_err):
        return jsonify({"error": f"File too large (max {MAX_UPLOAD_BYTES // (1024 * 1024)} MB)."}), 413

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
        with locked_store(_case_dir(case)) as store:
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

    @app.route("/api/cases/<case_id>/evidence", methods=["POST"])
    def upload_evidence(case_id):
        case = _load_case(case_id)
        if "file" not in request.files:
            raise ApiError("No file provided (expected multipart field 'file').")
        uploaded = request.files["file"]
        filename = secure_filename(uploaded.filename or "")
        if not filename:
            raise ApiError("No file selected, or filename is invalid.")

        staging_dir = Path(tempfile.mkdtemp(prefix="netforensic_upload_"))
        try:
            staging_path = staging_dir / filename
            uploaded.save(staging_path)

            evidence_manager = EvidenceManager(_case_dir(case))
            try:
                evidence = evidence_manager.add(staging_path, case_id=case.case_id)
            except EvidenceError as e:
                raise ApiError(str(e))
            case_manager.register_evidence(case.case_id, evidence.evidence_id)
        finally:
            shutil.rmtree(staging_dir, ignore_errors=True)

        return jsonify(evidence.to_dict()), 201

    # --- analyze (parse every evidence item + correlate, mirrors `netforensic analyze`) ---

    @app.route("/api/cases/<case_id>/analyze", methods=["POST"])
    def analyze_case(case_id):
        case = _load_case(case_id)
        from netforensicai.core.correlation import correlate_case
        from netforensicai.core.pipeline import parse_evidence_item

        items = EvidenceManager(_case_dir(case)).list()
        results = []
        with locked_store(_case_dir(case)) as store:
            for evidence in items:
                event_count, entity_count, error = parse_evidence_item(
                    evidence, _case_dir(case), case_manager, case.case_id, store
                )
                results.append(
                    {
                        "evidence_id": evidence.evidence_id,
                        "evidence_type": evidence.evidence_type,
                        "event_count": event_count,
                        "entity_count": entity_count,
                        "error": error,
                    }
                )
            correlate_case(store)
            total_entities = store.count_entities()
            total_events = store.count_events()

        return jsonify({"results": results, "total_events": total_events, "total_entities": total_entities})

    # --- timeline ---

    @app.route("/api/cases/<case_id>/timeline")
    def get_timeline(case_id):
        case = _load_case(case_id)
        with locked_store(_case_dir(case)) as store:
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
        with locked_store(_case_dir(case)) as store:
            items = store.list_entities(entity_type=entity_type)
        if query:
            items = [e for e in items if query in e["value"].lower()]
        return jsonify(items)

    @app.route("/api/cases/<case_id>/entities/<entity_id>/graph")
    def entity_graph(case_id, entity_id):
        case = _load_case(case_id)
        with locked_store(_case_dir(case)) as store:
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

        with locked_store(_case_dir(case)) as store:
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
        with locked_store(_case_dir(case)) as store:
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

        with locked_store(_case_dir(case)) as store:
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

    # --- ATT&CK technique mappings (read-only; run/validate via the CLI) ---

    @app.route("/api/cases/<case_id>/attack")
    def list_attack_techniques(case_id):
        case = _load_case(case_id)
        with locked_store(_case_dir(case)) as store:
            techniques = store.list_techniques()
        for t in techniques:
            t["created_at"] = t["created_at"].isoformat() if t["created_at"] else None
            t["updated_at"] = t["updated_at"].isoformat() if t["updated_at"] else None
        return jsonify(techniques)

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

    # --- live capture ---
    # Polled by the frontend rather than streamed (SSE): a persistent
    # streaming connection would need a threaded server, which conflicts
    # with keeping DuckDB access serialized through one global lock - see
    # the module docstring. ~1.5s polling is plenty responsive for this.

    @app.route("/api/interfaces")
    def api_list_interfaces():
        from netforensicai.core import capture as capture_module

        try:
            return jsonify(capture_module.list_interfaces())
        except Exception as e:
            raise ApiError(f"Could not list network interfaces: {e}", 500)

    @app.route("/api/cases/<case_id>/capture/status")
    def capture_status(case_id):
        case = _load_case(case_id)
        from netforensicai.core import capture as capture_module

        session = capture_module.get_session(case.case_id)
        if session is None:
            return jsonify({"running": False})
        return jsonify(session.snapshot())

    @app.route("/api/cases/<case_id>/capture/start", methods=["POST"])
    def capture_start(case_id):
        case = _load_case(case_id)
        from netforensicai.core import capture as capture_module

        payload = request.get_json(force=True, silent=True) or {}
        rotate_seconds = payload.get("rotate_seconds") or capture_module.DEFAULT_ROTATE_SECONDS
        try:
            rotate_seconds = int(rotate_seconds)
        except (TypeError, ValueError):
            raise ApiError("rotate_seconds must be an integer")

        try:
            capture_module.start_capture(
                case.case_id,
                _case_dir(case),
                case_manager,
                interface=payload.get("interface") or None,
                bpf_filter=payload.get("filter") or None,
                rotate_seconds=rotate_seconds,
            )
        except capture_module.CaptureError as e:
            status = 409 if "already running" in str(e) else 400
            raise ApiError(str(e), status)
        return jsonify({"started": True})

    @app.route("/api/cases/<case_id>/capture/stop", methods=["POST"])
    def capture_stop(case_id):
        case = _load_case(case_id)
        from netforensicai.core import capture as capture_module

        try:
            capture_module.stop_capture(case.case_id)
        except capture_module.CaptureError as e:
            raise ApiError(str(e), 404)
        return jsonify({"stopped": True})

    return app
