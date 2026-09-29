"""Recovered files: identification, risk, safe preview, path safety
(core/artifacts.py), the web routes that expose them, and stream bytes.

The preview rules exist so that looking at a hostile file cannot hurt the
person looking - these tests pin that nothing is ever offered for inline
rendering except raster images, and that a request can only reach files the
case itself registered.
"""

import pytest

from netforensicai.core import artifacts, audit
from netforensicai.core.case import CaseManager
from netforensicai.core.streams import _parse_raw_follow
from netforensicai.web.app import create_app

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
MZ = b"MZ\x90\x00" + b"\x00" * 60


def _write(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return path


# --- identify / risk -------------------------------------------------------


@pytest.mark.parametrize(
    "name, data, kind",
    [
        ("setup.exe", MZ, "executable"),
        ("x.bin", b"\x7fELF\x02\x01", "executable"),
        ("doc.pdf", b"%PDF-1.7\n", "pdf"),
        ("pic.png", PNG, "png"),
        ("pic.jpg", b"\xff\xd8\xff\xe0" + b"\x00" * 10, "jpeg"),
        ("a.zip", b"PK\x03\x04rest", "zip"),
        ("report.docx", b"PK\x03\x04rest", "office"),
        ("old.doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1rest", "office-legacy"),
        ("notes.txt", b"hello world\n", "text"),
        ("run.ps1", b"Write-Host hi\n", "script"),
        ("page.html", b"<!DOCTYPE html><html><script>alert(1)</script>", "html"),
        ("logo.svg", b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', "svg"),
        ("data.csv", b"a,b,c\n1,2,3\n", "csv"),
        ("blob", bytes(range(256)), "binary"),
    ],
)
def test_identify_by_content(tmp_path, name, data, kind):
    assert artifacts.identify(_write(tmp_path, name, data))["kind"] == kind


def test_disguised_program_is_called_out(tmp_path):
    path = _write(tmp_path, "invoice.pdf", MZ)
    level, reasons = artifacts._risk(path.name, artifacts.identify(path))
    assert level == "high"
    assert "Named '.pdf' but the content is a Windows program" in reasons[0]


def test_double_extension_only_for_decoy_extensions(tmp_path):
    level, reasons = artifacts._risk("invoice.pdf.exe", {"kind": "executable", "label": "Windows program (EXE/DLL)"})
    assert level == "high" and "Double extension" in reasons[0]
    _level, reasons = artifacts._risk("my.tool.exe", {"kind": "executable", "label": "Windows program (EXE/DLL)"})
    assert not any("Double extension" in r for r in reasons)


def test_plain_text_is_low_risk_and_notes_personal_data(tmp_path):
    data = b"name,email\n" + b"".join(b"u%d,u%d@corp.example\n" % (i, i) for i in range(5))
    path = _write(tmp_path, "people.csv", data)
    identity = artifacts.identify(path)
    assert artifacts._risk(path.name, identity)[0] == "low"
    assert any("email addresses" in n for n in artifacts._content_notes(data, identity["kind"]))


def test_private_key_note():
    notes = artifacts._content_notes(b"-----BEGIN OPENSSH PRIVATE KEY-----\nabc", "text")
    assert any("private key" in n for n in notes)


# --- preview ---------------------------------------------------------------


def test_preview_modes(tmp_path):
    assert artifacts.preview(_write(tmp_path, "p.png", PNG))["mode"] == "image"
    table = artifacts.preview(_write(tmp_path, "d.csv", b"a,b\n1,2\n3,4\n"))
    assert (table["mode"], table["header"], table["rows"]) == ("table", ["a", "b"], [["1", "2"], ["3", "4"]])
    assert artifacts.preview(_write(tmp_path, "e.txt", b""))["mode"] == "empty"
    hexed = artifacts.preview(_write(tmp_path, "m.exe", MZ))
    assert hexed["mode"] == "hex" and hexed["text"].startswith("00000000  4d 5a")


@pytest.mark.parametrize("name, data", [
    ("page.html", b"<html><script>alert(1)</script></html>"),
    ("logo.svg", b"<svg><script>alert(1)</script></svg>"),
])
def test_active_content_is_previewed_as_text_never_rendered(tmp_path, name, data):
    preview = artifacts.preview(_write(tmp_path, name, data))
    assert preview["mode"] == "text"
    assert "<script>" in preview["text"]  # shown literally; the UI sets it as textContent


# --- resolve (path safety) --------------------------------------------------


@pytest.fixture
def case_with_files(tmp_path):
    cases_dir = tmp_path / "cases"
    manager = CaseManager(cases_dir)
    case = manager.create(name="Files", investigator="analyst")
    case_dir = cases_dir / case.case_id
    (case_dir / "artifacts" / "EV-0001" / "http").mkdir(parents=True)
    (case_dir / "artifacts" / "EV-0001" / "http" / "setup.exe").write_bytes(MZ)
    (case_dir / "artifacts" / "EV-0001" / "http" / "pic.png").write_bytes(PNG)
    (case_dir / "artifacts" / "EV-0001" / "http" / "data.csv").write_bytes(b"a,b\n1,2\n")
    for name in ("setup.exe", "pic.png", "data.csv"):
        manager.register_artifact(case.case_id, f"artifacts/EV-0001/http/{name}")
    (tmp_path / "secret.txt").write_text("outside the case", encoding="utf-8")
    return cases_dir, manager, case.case_id


def test_resolve_refuses_anything_not_registered_or_outside(case_with_files, tmp_path):
    cases_dir, manager, case_id = case_with_files
    case = manager.load(case_id)
    case_dir = cases_dir / case_id
    assert artifacts.resolve(case_dir, case, "artifacts/EV-0001/http/setup.exe").name == "setup.exe"
    for bad in ("case.json", "../secret.txt", "artifacts/EV-0001/http/../../../case.json", "", None):
        with pytest.raises(artifacts.ArtifactError):
            artifacts.resolve(case_dir, case, bad)

    # A tampered case.json registering a path outside artifacts/ is still refused.
    manager.register_artifact(case_id, "../../secret.txt")
    with pytest.raises(artifacts.ArtifactError):
        artifacts.resolve(case_dir, manager.load(case_id), "../../secret.txt")


# --- web routes -------------------------------------------------------------


def test_web_list_preview_and_download(case_with_files):
    cases_dir, _manager, case_id = case_with_files
    client = create_app(cases_dir).test_client()

    rows = {r["name"]: r for r in client.get(f"/api/cases/{case_id}/artifacts").get_json()}
    assert rows["setup.exe"]["risk"] == "high"
    assert rows["setup.exe"]["type"]["label"] == "Windows program (EXE/DLL)"
    assert rows["data.csv"]["previewable_image"] is False
    assert rows["pic.png"]["previewable_image"] is True
    assert len(rows["setup.exe"]["sha256"]) == 64

    preview = client.get(f"/api/cases/{case_id}/artifacts/preview", query_string={"path": rows["data.csv"]["path"]})
    assert preview.get_json()["mode"] == "table"

    download = client.get(f"/api/cases/{case_id}/artifacts/content", query_string={"path": rows["setup.exe"]["path"]})
    assert download.status_code == 200
    assert download.data == MZ
    assert download.headers["Content-Type"] == "application/octet-stream"
    assert download.headers["Content-Disposition"].startswith("attachment")
    assert download.headers["X-Content-Type-Options"] == "nosniff"
    assert "sandbox" in download.headers["Content-Security-Policy"]

    [entry] = [e for e in audit.read_entries(cases_dir / case_id) if e["action"] == audit.ARTIFACT_EXPORTED]
    assert entry["details"]["path"] == rows["setup.exe"]["path"]
    assert entry["details"]["sha256"] == rows["setup.exe"]["sha256"]
    assert audit.verify(cases_dir / case_id)[0]


def test_web_inline_only_for_raster_images_and_not_audited(case_with_files):
    cases_dir, _manager, case_id = case_with_files
    client = create_app(cases_dir).test_client()

    image = client.get(f"/api/cases/{case_id}/artifacts/content",
                       query_string={"path": "artifacts/EV-0001/http/pic.png", "inline": "1"})
    assert image.status_code == 200
    assert image.headers["Content-Type"] == "image/png"

    exe = client.get(f"/api/cases/{case_id}/artifacts/content",
                     query_string={"path": "artifacts/EV-0001/http/setup.exe", "inline": "1"})
    assert exe.status_code == 400
    assert [e for e in audit.read_entries(cases_dir / case_id) if e["action"] == audit.ARTIFACT_EXPORTED] == []


def test_web_refuses_unregistered_paths(case_with_files):
    cases_dir, _manager, case_id = case_with_files
    client = create_app(cases_dir).test_client()
    for path in ("case.json", "../secret.txt", "artifacts/EV-0001/http/../../../case.json"):
        for route in ("content", "preview"):
            resp = client.get(f"/api/cases/{case_id}/artifacts/{route}", query_string={"path": path})
            assert resp.status_code == 404, (route, path)


def test_missing_file_is_listed_not_hidden(case_with_files):
    cases_dir, _manager, case_id = case_with_files
    (cases_dir / case_id / "artifacts" / "EV-0001" / "http" / "pic.png").unlink()
    rows = {r["name"]: r for r in create_app(cases_dir).test_client().get(f"/api/cases/{case_id}/artifacts").get_json()}
    assert rows["pic.png"]["missing"] is True
    assert rows["pic.png"]["size_bytes"] is None


# --- stream bytes -------------------------------------------------------------


RAW_FOLLOW = (
    "===================================================================\n"
    "Follow: tcp,raw\n"
    "Filter: tcp.stream eq 4\n"
    "Node 0: 10.0.0.5:50000\n"
    "Node 1: 10.0.0.9:21\n"
    "\t3232300d0a\n"
    "55534552206a6f650d0a\n"
    "\t00ff0d0a\n"
    "===================================================================\n"
)


def test_raw_follow_is_decoded_byte_exact_by_direction():
    payload = _parse_raw_follow(RAW_FOLLOW, "tcp", 4, max_bytes=1024)
    assert (payload.node_a, payload.node_b) == ("10.0.0.5:50000", "10.0.0.9:21")
    assert payload.a_to_b == b"USER joe\r\n"
    assert payload.b_to_a == b"220\r\n\x00\xff\r\n"  # CR/LF and non-printables kept exactly
    assert payload.truncated is False


def test_raw_follow_cap_and_missing_stream():
    assert _parse_raw_follow(RAW_FOLLOW, "tcp", 4, max_bytes=6).truncated is True
    from netforensicai.core.streams import StreamError

    with pytest.raises(StreamError):
        _parse_raw_follow("Follow: tcp,raw\nNode 0: :0\nNode 1: :0\n", "tcp", 99, max_bytes=1024)


# --- email (exfiltration by mail is common; its body is usually base64) ------

import base64  # noqa: E402

EML = (
    b"MIME-Version: 1.0\r\nFrom: thief@example.org\r\nTo: drop@example.org\r\n"
    b"Date: Wed, 10 Apr 2019 20:48:18 +0000\r\n"
    b"Subject: =?utf-8?B?" + base64.b64encode("Passwords Logs - victim".encode()) + b"?=\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n"
    + base64.b64encode(b"Application : Outlook\r\nPassword    : hunter2\r\n") + b"\r\n"
)


def test_email_is_identified_decoded_and_hinted(tmp_path):
    path = _write(tmp_path, "loot.eml", EML)
    assert artifacts.identify(path)["kind"] == "email"
    level, reasons, text = artifacts._email_risk(path, "low", [], EML[:100])
    assert level == "low"
    assert any("password field" in n for n in artifacts._content_notes(text, "email"))

    preview = artifacts.preview(path)
    assert preview["mode"] == "email"
    assert preview["headers"]["subject"] == "Passwords Logs - victim"  # MIME-decoded
    assert preview["headers"]["from"] == "thief@example.org"
    assert "Password    : hunter2" in preview["body"]  # base64-decoded
    assert preview["attachments"] == []


def test_email_carrying_a_program_is_high_risk(tmp_path):
    from email.message import EmailMessage

    message = EmailMessage()
    message["From"], message["To"], message["Subject"] = "a@example.org", "b@example.org", "invoice"
    message.set_content("see attached")
    message.add_attachment(MZ, maintype="application", subtype="octet-stream", filename="invoice.pdf.exe")
    path = _write(tmp_path, "mail.eml", message.as_bytes())

    level, reasons, _text = artifacts._email_risk(path, "low", [], b"")
    assert level == "high"
    assert "invoice.pdf.exe" in reasons[0]
    assert artifacts.preview(path)["attachments"][0]["name"] == "invoice.pdf.exe"


# --- scale and path handling ---------------------------------------------------


def test_sources_match_by_path_tail_in_one_pass(tmp_path):
    # Events record file_path as seen from wherever analysis ran - absolute,
    # relative, Windows or POSIX separators. All must match their artifact.
    from netforensicai.core.event import Event
    from netforensicai.core.store import CaseStore

    paths = [f"artifacts/EV-0001/http/f{i}.bin" for i in range(3)]
    recorded = [
        r"C:\cases\INC-0001\artifacts\EV-0001\http\f0.bin",
        "../cases/INC-0001/artifacts/EV-0001/http/f1.bin",
        "/srv/nf/cases/INC-0001/artifacts/EV-0001/http/f2.bin",
    ]
    events = [
        Event(event_id=f"E{i}", evidence_id="EV-0001", source="pcap", event_type="file_transfer", file_path=p)
        for i, p in enumerate(recorded)
    ]
    with CaseStore(tmp_path) as store:
        store.replace_events_for_evidence("EV-0001", events)
        found = artifacts._sources(store, paths)
    assert {path: found[path].event_id for path in paths} == {paths[0]: "E0", paths[1]: "E1", paths[2]: "E2"}


def test_hash_cache_tracks_changes(tmp_path):
    path = _write(tmp_path, "f.bin", b"one")
    first = artifacts.cached_sha256(path)
    assert artifacts.cached_sha256(path) == first
    import os
    import time

    path.write_bytes(b"two!")  # different size -> recomputed
    os.utime(path, ns=(time.time_ns(), time.time_ns()))
    assert artifacts.cached_sha256(path) == artifacts.sha256_of(path) != first


def test_fs_path_long_form_only_on_windows_long_paths(monkeypatch):
    monkeypatch.setattr(artifacts.os, "name", "nt")
    # Raw strings throughout: these are Windows paths, backslashes and all.
    long_path = r"C:\data" + "a" * 300
    assert str(artifacts._long_form(long_path)).startswith(r"\\?\C:\data")
    assert str(artifacts._long_form(r"C:\short")) == r"C:\short"
    unc = r"\\server\share" + "\\" + "b" * 300
    assert str(artifacts._long_form(unc)).startswith(r"\\?\UNC\server\share")


def test_tar_is_recognised_at_its_real_offset(tmp_path):
    data = b"\x00" * 257 + b"ustar\x0000" + b"\x00" * 300
    assert artifacts.identify(_write(tmp_path, "a.tar", data))["label"] == "TAR archive"


def test_name_promising_a_format_the_content_lacks_is_flagged(tmp_path):
    # Seen on a real capture: backup.sql.gz and archive.tar holding random bytes.
    path = _write(tmp_path, "backup.sql.gz", bytes(range(256)) * 4)
    level, reasons = artifacts._risk(path.name, artifacts.identify(path))
    assert level == "medium"
    assert "may be encrypted, corrupted, or disguised" in reasons[-1]
    # A genuine archive of the named type is not flagged.
    gz = _write(tmp_path, "real.gz", b"\x1f\x8b\x08\x00" + b"\x00" * 20)
    assert not any("not that format" in r for r in artifacts._risk(gz.name, artifacts.identify(gz))[1])
