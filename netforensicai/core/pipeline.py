"""Shared evidence -> events -> entities ingestion pipeline.

This is the one place that logic lives: cli.py's `parse`/`analyze`
commands, the web UI's evidence-upload/analyze endpoints, and the live
capture module's per-rotation ingestion all call parse_evidence_item()
rather than each having their own copy.
"""

import logging
import os

logger = logging.getLogger(__name__)


def parse_evidence_item(evidence, case_dir, case_manager, case_id, store):
    """Parse one evidence item, persist its events + extracted entities into
    `store`, and register any newly saved artifact files against the case.

    Returns (event_count, entity_count, error). error is None on success.
    """
    from netforensicai.core.entities import extract_and_store
    from netforensicai.core.evidence import EvidenceManager
    from netforensicai.parsers import base, load_parsers

    load_parsers()
    parser = base.get_parser(evidence.evidence_type)
    if parser is None:
        return None, None, f"No parser registered for evidence type '{evidence.evidence_type}'"

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
