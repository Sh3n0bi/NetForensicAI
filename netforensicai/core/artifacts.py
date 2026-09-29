"""Recovered files: what each one really is, where it came from, and a way to
look at it that cannot hurt the person looking.

Files carved out of evidence (HTTP downloads, SMB shares, FTP transfers, email
attachments) land under cases/<id>/artifacts/ and are listed in the case's
artifact index. This module is everything the Files view needs on top of that:

  - resolve()   the ONLY way a request turns into a path on disk: the path must
                be one the case registered, and must stay inside artifacts/.
  - identify()  the file's real type from its first bytes, not its name - a
                "report.pdf" that starts with "MZ" is a Windows program, and
                saying so is the single most useful thing this view can do.
  - describe()  identity plus plain-language risk notes and hints about the
                content (e.g. "contains email addresses").
  - preview()   text, a CSV table, a safe raster image, or a hex dump. Nothing
                from a recovered file is ever executed or rendered as HTML;
                images are only offered for formats that cannot carry script.

Everything here is read-only: listing, identifying and previewing a file never
changes it or the case.
"""

import csv
import hashlib
import io
import re
from pathlib import Path

ARTIFACTS_DIRNAME = "artifacts"
SNIFF_BYTES = 8192
PREVIEW_TEXT_BYTES = 64 * 1024
PREVIEW_HEX_BYTES = 2048
PREVIEW_CSV_ROWS = 100
PREVIEW_CSV_COLUMNS = 30

# Raster formats a browser decodes without running anything. SVG is XML that
# can carry script, so it is deliberately NOT here - it is shown as text.
SAFE_IMAGE_MIME = {"png": "image/png", "jpeg": "image/jpeg", "gif": "image/gif", "webp": "image/webp"}

# (prefix, kind, label). Checked in order; the first match wins.
_MAGIC = (
    (b"MZ", "executable", "Windows program (EXE/DLL)"),
    (b"\x7fELF", "executable", "Linux program (ELF)"),
    (b"\xcf\xfa\xed\xfe", "executable", "macOS program (Mach-O)"),
    (b"\xce\xfa\xed\xfe", "executable", "macOS program (Mach-O)"),
    (b"\xca\xfe\xba\xbe", "executable", "macOS or Java program"),
    (b"%PDF", "pdf", "PDF document"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "office-legacy", "Legacy Office document (DOC/XLS/PPT)"),
    (b"PK\x03\x04", "zip", "ZIP archive"),
    (b"\x1f\x8b", "archive", "GZIP archive"),
    (b"Rar!\x1a\x07", "archive", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "archive", "7-Zip archive"),
    (b"\x89PNG\r\n\x1a\n", "png", "PNG image"),
    (b"\xff\xd8\xff", "jpeg", "JPEG image"),
    (b"GIF87a", "gif", "GIF image"),
    (b"GIF89a", "gif", "GIF image"),
)

_OFFICE_ZIP_EXTENSIONS = {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"}
_MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".doc", ".xls", ".ppt"}
_EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".scr", ".com", ".pif", ".msi", ".sys", ".cpl"}
# What a disguised program pretends to be, as in "invoice.pdf.exe".
_DECOY_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".csv",
                     ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".zip"}
_SCRIPT_EXTENSIONS = {".ps1", ".vbs", ".js", ".jse", ".bat", ".cmd", ".hta", ".wsf", ".sh", ".py"}

_EMAIL = re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PRIVATE_KEY = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PASSWORDISH = re.compile(rb"(?i)\b(pass(word|wd)?|pwd)\s*[=:]")


class ArtifactError(Exception):
    """Raised for an artifact that is not registered, missing, or unsafe."""


def resolve(case_dir, case, relative_path):
    """The on-disk path for a registered artifact, or ArtifactError.

    Two checks, both required. The path must be one the case itself
    registered (so a request can only name files the tool recovered), and it
    must resolve inside the case's artifacts/ directory (so a tampered
    case.json cannot point it at anything else on the machine).
    """
    relative_path = (relative_path or "").replace("\\", "/")
    if relative_path not in (case.artifacts or []):
        raise ArtifactError("Not a recovered file in this case.")
    root = (Path(case_dir) / ARTIFACTS_DIRNAME).resolve()
    path = (Path(case_dir) / relative_path).resolve()
    if root not in path.parents:
        raise ArtifactError("Not a recovered file in this case.")
    if not path.is_file():
        raise ArtifactError("This recovered file is missing from the case directory.")
    return path


def _head(path, n=SNIFF_BYTES):
    with open(path, "rb") as handle:
        return handle.read(n)


def _looks_like_text(data):
    if not data:
        return True
    if b"\x00" in data:
        return False
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as e:
        # A multi-byte character cut at the sniff boundary is still text.
        if e.start < len(data) - 4:
            return False
    control = sum(1 for b in data if b < 9 or 13 < b < 32)
    return control / len(data) < 0.02


def identify(path, head=None):
    """{kind, label, mime} for a file, decided by its content."""
    head = _head(path) if head is None else head
    extension = Path(path).suffix.lower()
    for prefix, kind, label in _MAGIC:
        if head.startswith(prefix):
            if kind == "zip" and extension in _OFFICE_ZIP_EXTENSIONS:
                return {"kind": "office", "label": "Office document (ZIP-based)", "mime": "application/zip"}
            if kind == "zip" and extension in {".jar", ".apk"}:
                return {"kind": "executable", "label": "Java/Android package", "mime": "application/zip"}
            return {"kind": kind, "label": label, "mime": SAFE_IMAGE_MIME.get(kind, "application/octet-stream")}
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return {"kind": "webp", "label": "WebP image", "mime": "image/webp"}
    if _looks_like_text(head):
        lowered = head[:512].lstrip().lower()
        if lowered.startswith(b"#!") or extension in _SCRIPT_EXTENSIONS:
            return {"kind": "script", "label": "Script", "mime": "text/plain"}
        # SVG before HTML: an SVG carrying <script> is still an SVG, just a
        # hostile one - both are only ever shown as text.
        if b"<svg" in lowered:
            return {"kind": "svg", "label": "SVG image (shown as text)", "mime": "text/plain"}
        if lowered.startswith((b"<!doctype html", b"<html")) or b"<script" in lowered:
            return {"kind": "html", "label": "Web page (HTML)", "mime": "text/plain"}
        if extension in {".csv", ".tsv"} or _looks_like_csv(head):
            return {"kind": "csv", "label": "Table (CSV)", "mime": "text/plain"}
        return {"kind": "text", "label": "Text", "mime": "text/plain"}
    return {"kind": "binary", "label": "Binary data", "mime": "application/octet-stream"}


def _looks_like_csv(head):
    lines = [line for line in head.split(b"\n")[:6] if line.strip()]
    if len(lines) < 2:
        return False
    counts = {line.count(b",") for line in lines}
    return len(counts) == 1 and counts.pop() >= 2


def _content_notes(head, kind):
    """Plain-language hints about what the content holds - leads, not verdicts."""
    notes = []
    if _PRIVATE_KEY.search(head):
        notes.append("Contains a private key - whoever holds this file can impersonate its owner.")
    emails = len(set(_EMAIL.findall(head)))
    if emails >= 3:
        notes.append(f"Contains {emails}+ email addresses - may be personal data.")
    if kind in ("text", "csv") and _PASSWORDISH.search(head):
        notes.append("Mentions a password field - may contain credentials.")
    return notes


def _risk(name, identity):
    """(level, reasons). 'high' = could run code if opened; 'medium' = can carry
    active content; 'low' otherwise. Always explained in plain words."""
    extension = Path(name).suffix.lower()
    kind = identity["kind"]
    reasons = []
    level = "low"
    if kind == "executable":
        level = "high"
        reasons.append("This is a program. Opening it would run it - only open it in an isolated analysis machine.")
    elif kind == "script" or extension in _SCRIPT_EXTENSIONS:
        level = "high"
        reasons.append("This is a script. Opening it may run it.")
    elif kind in ("office-legacy",) or extension in _MACRO_EXTENSIONS:
        level = "medium"
        reasons.append("Office document that can contain macros.")
    elif kind in ("pdf", "html", "svg", "office"):
        level = "medium"
        reasons.append(f"{identity['label']} can contain active content; open it only in a safe viewer.")
    elif kind in ("zip", "archive"):
        level = "medium"
        reasons.append("Archive - the files inside have not been checked.")

    claimed_program = extension in _EXECUTABLE_EXTENSIONS
    if kind == "executable" and extension and not claimed_program and extension not in {".jar", ".apk"}:
        level = "high"
        reasons.insert(0, f"Named '{extension}' but the content is a {identity['label']} - disguised program.")
    elif claimed_program and kind != "executable":
        reasons.append(f"Named '{extension}' but the content is not a program ({identity['label']}).")
    stem_extension = Path(Path(name).stem).suffix.lower()
    if stem_extension in _DECOY_EXTENSIONS and extension in _EXECUTABLE_EXTENSIONS | _SCRIPT_EXTENSIONS:
        level = "high"
        reasons.insert(0, f"Double extension ('{stem_extension}{extension}') - a common way to disguise malware.")
    return level, reasons


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sources(store, artifact_paths):
    """{artifact relative path: file_transfer event} - where each file came from.

    Matched on the path's tail, not by recomputing a relative path: an event
    records file_path as it looked from wherever the analysis ran (often a
    relative path against that process's working directory), so relpath()
    from here would only match when both happened to run from the same place.
    """
    wanted = {path: "/" + path.lstrip("/") for path in artifact_paths}
    found = {}
    for event in store.iter_events("WHERE event_type = ?", ("file_transfer",)):
        if not event.file_path:
            continue
        recorded = "/" + event.file_path.replace("\\", "/").lstrip("/")
        for path, tail in wanted.items():
            if path not in found and recorded.endswith(tail):
                found[path] = event
                break
    return found


def _http_origins(store):
    """{file name: (from, to, url)} from HTTP events, for exported HTTP objects.

    Wireshark's HTTP export names each file after the last part of its URL but
    does not say which exchange it came from. The HTTP events do: a response
    carrying the file means it was downloaded from that server; a POST means
    the client sent it. A response is preferred when both exist.
    """
    origins = {}
    for event in store.iter_events("WHERE event_type IN (?, ?)", ("http_response", "http_request")):
        if not event.url:
            continue
        name = event.url.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]
        if not name:
            continue
        method = (event.raw_event_reference or {}).get("method")
        is_download = event.event_type == "http_response"
        is_upload = method in ("POST", "PUT") and name not in origins
        if is_download or is_upload:
            origins[name] = (event.src_ip, event.dst_ip, event.url)
    return origins


def describe_all(case_dir, case, store):
    """Every registered artifact, described. Missing files are listed, not hidden."""
    case_dir = Path(case_dir)
    sources = _sources(store, case.artifacts or [])
    http_origins = None
    rows = []
    for relative in case.artifacts or []:
        path = case_dir / relative
        row = {
            "path": relative,
            "name": Path(relative).name,
            "protocol": Path(relative).parent.name,
            "missing": not path.is_file(),
            "size_bytes": None,
        }
        event = sources.get(relative)
        if event is not None:
            reference = event.raw_event_reference or {}
            row["source"] = {
                "event_id": event.event_id,
                "evidence_id": event.evidence_id,
                "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                "from": event.src_ip,
                "to": event.dst_ip,
                "summary": event.message,
                "stream": reference.get("stream"),
                "recovered_by": reference.get("recovered_by") or "wireshark-export",
            }
            if row["protocol"] == "http" and not event.src_ip:
                if http_origins is None:
                    http_origins = _http_origins(store)
                origin = http_origins.get(row["name"])
                if origin:
                    row["source"]["from"], row["source"]["to"], row["source"]["url"] = origin
        if not row["missing"]:
            head = _head(path)
            identity = identify(path, head)
            level, reasons = _risk(row["name"], identity)
            row.update(
                size_bytes=path.stat().st_size,
                sha256=sha256_of(path),
                type=identity,
                risk=level,
                risk_reasons=reasons,
                notes=_content_notes(head, identity["kind"]),
                previewable_image=identity["kind"] in SAFE_IMAGE_MIME,
            )
        rows.append(row)
    return rows


def _hexdump(data):
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        text_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:08x}  {hex_part:<47}  {text_part}")
    return "\n".join(lines)


def preview(path):
    """A safe way to look at a file. Never returns anything meant to be
    rendered as HTML: text is text, images are raster-only and fetched
    separately, everything else is a hex dump."""
    size = path.stat().st_size
    head = _head(path, max(PREVIEW_TEXT_BYTES, PREVIEW_HEX_BYTES))
    identity = identify(path, head[:SNIFF_BYTES])
    kind = identity["kind"]
    if size == 0:
        return {"mode": "empty", "type": identity}
    if kind in SAFE_IMAGE_MIME:
        return {"mode": "image", "type": identity}
    if kind == "csv":
        text = head[:PREVIEW_TEXT_BYTES].decode("utf-8", errors="replace")
        rows = []
        for row in csv.reader(io.StringIO(text)):
            rows.append(row[:PREVIEW_CSV_COLUMNS])
            if len(rows) >= PREVIEW_CSV_ROWS + 1:
                break
        return {
            "mode": "table",
            "type": identity,
            "header": rows[0] if rows else [],
            "rows": rows[1:],
            "truncated": size > PREVIEW_TEXT_BYTES or len(rows) > PREVIEW_CSV_ROWS,
        }
    if kind in ("text", "script", "html", "svg"):
        return {
            "mode": "text",
            "type": identity,
            "text": head[:PREVIEW_TEXT_BYTES].decode("utf-8", errors="replace"),
            "truncated": size > PREVIEW_TEXT_BYTES,
        }
    return {
        "mode": "hex",
        "type": identity,
        "text": _hexdump(head[:PREVIEW_HEX_BYTES]),
        "truncated": size > PREVIEW_HEX_BYTES,
    }
