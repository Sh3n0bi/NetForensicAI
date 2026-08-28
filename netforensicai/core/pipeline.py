"""Shared evidence -> events -> entities ingestion pipeline.

This is the one place that logic lives: cli.py's `parse`/`analyze`
commands, the web UI's evidence-upload/analyze endpoints, and the live
capture module's per-rotation ingestion all call parse_evidence_item()
rather than each having their own copy.
"""

import itertools
import logging
import os

logger = logging.getLogger(__name__)

# Events held in memory at once while ingesting. Large enough that the bulk
# INSERT path stays efficient, small enough that a capture yielding hundreds
# of thousands of events never materializes them all - peak memory here is a
# function of this constant, not of the size of the evidence file.
INGEST_BATCH_SIZE = 5_000


def _batched(iterable, size):
    iterator = iter(iterable)
    while True:
        batch = list(itertools.islice(iterator, size))
        if not batch:
            return
        yield batch


def parse_evidence_item(evidence, case_dir, case_manager, case_id, store, parse_options=None):
    """Parse one evidence item, persist its events + extracted entities into
    `store`, and register any newly saved artifact files against the case.

    Events are streamed from the parser and written in batches rather than
    collected into a single list first - see INGEST_BATCH_SIZE.

    parse_options are format-specific knobs forwarded to the parser, e.g.
    the pcap dispatcher's `engine` and `display_filter`. They are threaded
    through this one function rather than applied by each caller so that
    however an item was ingested - CLI, web upload, live-capture rotation
    - the options end up in the audit trail identically. Parsers ignore
    options they don't recognize (BaseParser takes **options), so a
    pcap-specific knob reaching a JSON evidence item is harmless.

    Returns (event_count, entity_count, error). error is None on success.
    """
    parse_options = {k: v for k, v in (parse_options or {}).items() if v is not None}

    from netforensicai.core.entities import extract_and_store_ids
    from netforensicai.core.evidence import EvidenceManager
    from netforensicai.parsers import base, load_parsers

    load_parsers()
    parser = base.get_parser(evidence.evidence_type)
    if parser is None:
        return None, None, f"No parser registered for evidence type '{evidence.evidence_type}'"

    stored_path = EvidenceManager(case_dir).stored_file_path(evidence.evidence_id)
    output_dir = case_dir / "artifacts" / evidence.evidence_id

    event_count = 0
    entity_ids = set()
    artifact_paths = []
    try:
        store.delete_events_for_evidence(evidence.evidence_id)
        stream = parser.iter_parse(
            stored_path,
            evidence_id=evidence.evidence_id,
            output_dir=str(output_dir),
            **parse_options,
        )
        for batch in _batched(stream, INGEST_BATCH_SIZE):
            store.insert_events(batch)
            # Union of ids, not a sum of per-batch counts: the same entity
            # recurs across batches, and adding counts would inflate the
            # total by exactly the overlap correlation exists to surface.
            entity_ids |= extract_and_store_ids(store, batch)
            event_count += len(batch)
            for event in batch:
                if event.event_type == "file_transfer" and event.file_path:
                    artifact_paths.append(
                        os.path.relpath(event.file_path, case_dir).replace(os.sep, "/")
                    )
    except Exception as e:
        # All-or-nothing from the case's point of view: a partially ingested
        # evidence item is worse than none, because every later stage
        # (correlation, detections, the timeline, the report) would silently
        # reason over half a file with no indication anything was missing.
        store.delete_events_for_evidence(evidence.evidence_id)
        return None, None, str(e)

    for relative_path in artifact_paths:
        case_manager.register_artifact(case_id, relative_path)

    from netforensicai.core import audit

    audit.record(
        case_dir,
        audit.EVIDENCE_PARSED,
        {
            "evidence_id": evidence.evidence_id,
            "evidence_type": evidence.evidence_type,
            "event_count": event_count,
            "entity_count": len(entity_ids),
            "artifacts_extracted": len(artifact_paths),
            # Recorded because "which dissector produced these events, and
            # was the capture filtered on the way in" are questions a
            # defensible report has to answer months later, on a machine
            # that may no longer have the same tooling installed.
            **({"parse_options": parse_options} if parse_options else {}),
        },
    )

    return event_count, len(entity_ids), None
