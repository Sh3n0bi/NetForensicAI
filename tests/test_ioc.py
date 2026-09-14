"""Tests for importing threat-intelligence indicators and matching them.

The failures that matter here are quiet ones. A defanged indicator stored
verbatim never matches anything. A /8 pasted into a feed matches
everything. A match written outside the detection pass vanishes on the
next analyze. None of those raise; each one just makes the feature lie.
"""

import io
import json
from datetime import datetime, timedelta, timezone

import pytest
from typer.testing import CliRunner

from netforensicai.core import audit, ioc
from netforensicai.core import narrative as narrative_module
from netforensicai.core.case import CaseManager
from netforensicai.core.detections import scan_case
from netforensicai.core.entities import extract_and_store
from netforensicai.core.event import Event
from netforensicai.core.store import CaseStore

BASE = datetime(2026, 9, 14, 9, 0, tzinfo=timezone.utc)
SHA256 = "a" * 64


def _event(index, offset=0, **fields):
    base = dict(
        event_id=f"EVT-EV-0001-{index:06d}",
        evidence_id="EV-0001",
        source="pcap",
        event_type="network_connection",
        timestamp=BASE + timedelta(seconds=offset),
    )
    base.update(fields)
    return Event(**base)


EVENTS = [
    _event(1, 0, event_type="dns_query", src_ip="10.0.0.5", domain="cdn.evil.top"),
    _event(2, 5, src_ip="10.0.0.5", dst_ip="45.33.32.156", dst_port=443),
    _event(3, 9, src_ip="10.0.0.5", dst_ip="45.33.32.156", dst_port=443),
    _event(4, 12, event_type="http_request", src_ip="10.0.0.5", dst_ip="93.184.216.34",
           url="http://Downloads.Example.com:80/payload.bin", domain="downloads.example.com"),
    _event(5, 20, event_type="file_transfer", file_name="x.exe", file_hash=SHA256.upper()),
    _event(6, 30, src_ip="10.0.0.5", dst_ip="8.8.8.8", dst_port=53),
]


@pytest.fixture
def case(tmp_path):
    cases_dir = tmp_path / "cases"
    created = CaseManager(cases_dir).create(name="IOC", investigator="analyst")
    case_dir = cases_dir / created.case_id
    with CaseStore(case_dir) as store:
        store.replace_events_for_evidence("EV-0001", EVENTS)
        extract_and_store(store, EVENTS)
    return cases_dir, created.case_id, case_dir


# --- classification -----------------------------------------------------


@pytest.mark.parametrize(
    "raw, ioc_type, value",
    [
        ("d41d8cd98f00b204e9800998ecf8427e", "md5", "d41d8cd98f00b204e9800998ecf8427e"),
        ("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", "sha1", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        (SHA256, "sha256", SHA256),
        ("hxxp://evil[.]top/drop", "url", "http://evil.top/drop"),
        ("HTTPS://Evil.Top:443/A", "url", "https://evil.top/A"),
        ("45.33.32[.]156", "ip", "45.33.32.156"),
        ("45.33.32.156/32", "ip", "45.33.32.156"),
        ("45.33.32.0/24", "cidr", "45.33.32.0/24"),
        ("Evil.Top.", "domain", "evil.top"),
        ("attacker[@]evil(.)top", "email", "attacker@evil.top"),
    ],
)
def test_indicators_are_refanged_and_normalized(raw, ioc_type, value):
    """Defanged values are how indicators arrive from reports. Stored
    verbatim they would import cleanly and never match anything."""
    indicator, reason = ioc.classify(raw)

    assert reason is None
    assert (indicator.ioc_type, indicator.value) == (ioc_type, value)


@pytest.mark.parametrize(
    "raw, reason_fragment",
    [
        ("10.0.0.0/8", "too broad"),
        ("127.0.0.1", "loopback"),
        ("localhost", "single-label"),
        ("not an indicator at all", "not a recognisable"),
        ("javascript:alert(1)", "not a recognisable"),
    ],
)
def test_dangerous_or_meaningless_indicators_are_refused_with_a_reason(raw, reason_fragment):
    """A /8 would flag every internal flow in a normal network - one bad
    line teaching the analyst to ignore every match."""
    indicator, reason = ioc.classify(raw)

    assert indicator is None
    assert reason_fragment in reason


def test_a_declared_hash_type_that_disagrees_with_the_value_is_refused():
    """Stored under the declared type, it could never match."""
    indicator, reason = ioc.classify("d41d8cd98f00b204e9800998ecf8427e", hinted_type="sha256")

    assert indicator is None
    assert "md5" in reason


# --- feed formats -------------------------------------------------------


def test_plain_text_feed_skips_comments_and_counts_duplicates():
    feed = "# campaign X\n\nevil.top  # stager\nEVIL.top\n45.33.32.156\n"
    result = ioc.parse_feed(feed)

    assert {(i.ioc_type, i.value) for i in result.indicators} == {("domain", "evil.top"), ("ip", "45.33.32.156")}
    assert result.duplicates == 1
    assert next(i for i in result.indicators if i.value == "evil.top").description == "stager"


def test_csv_with_header_uses_type_value_and_description_columns():
    feed = "type,indicator,description\nsha256,%s,loader\ndomain,evil.top,c2\n" % SHA256
    result = ioc.parse_feed(feed, "feed.csv")

    assert result.feed_format == "csv"
    assert {i.value: i.description for i in result.indicators} == {SHA256: "loader", "evil.top": "c2"}


def test_headerless_csv_takes_the_first_column_and_keeps_the_rest_as_notes():
    """Splitting every cell would report each note as a rejected
    indicator and bury the rejections that matter."""
    result = ioc.parse_feed("1.2.3.4,malware c2\nevil.top,phishing\n", "feed.csv")

    assert {i.value: i.description for i in result.indicators} == {"1.2.3.4": "malware c2", "evil.top": "phishing"}
    assert result.rejected == []


def _stix(*patterns, extra=()):
    objects = [
        {"type": "indicator", "spec_version": "2.1", "pattern_type": "stix", "pattern": p, "name": "test"}
        for p in patterns
    ]
    return json.dumps({"type": "bundle", "id": "bundle--1", "objects": objects + list(extra)})


def test_stix_single_and_ored_comparisons_are_imported():
    feed = _stix(
        "[ipv4-addr:value = '45.33.32.156']",
        "[domain-name:value = 'evil.top'] OR [url:value = 'http://evil.top/a']",
        "[file:hashes.'SHA-256' = '%s']" % SHA256,
    )
    result = ioc.parse_feed(feed)

    assert result.feed_format == "stix"
    assert {i.ioc_type for i in result.indicators} == {"ip", "domain", "url", "sha256"}


def test_stix_compound_pattern_is_refused_not_split():
    """[a] AND [b] is an indicator only when both hold. Importing a and b
    separately would match far more than the author meant."""
    feed = _stix("[ipv4-addr:value = '45.33.32.156'] AND [domain-name:value = 'evil.top']")
    result = ioc.parse_feed(feed)

    assert result.indicators == []
    assert "compound" in result.rejected[0][1]


def test_stix_operator_words_inside_a_value_do_not_trigger_the_refusal():
    feed = _stix("[url:value = 'http://evil.top/search?q=cats AND dogs']")
    result = ioc.parse_feed(feed)

    assert [i.ioc_type for i in result.indicators] == ["url"]


def test_misp_to_ids_false_is_skipped_and_composites_are_split():
    """to_ids = false is a MISP analyst saying "context, do not alert"."""
    feed = json.dumps({"response": [{"Event": {
        "info": "Campaign X",
        "Attribute": [
            {"type": "ip-dst", "value": "45.33.32.156", "to_ids": True},
            {"type": "ip-dst", "value": "8.8.8.8", "to_ids": False, "comment": "resolver the implant used"},
        ],
        "Object": [{"Attribute": [
            {"type": "filename|sha256", "value": f"loader.exe|{SHA256}", "to_ids": True},
        ]}],
    }}]})
    result = ioc.parse_feed(feed)

    assert result.feed_format == "misp"
    assert {(i.ioc_type, i.value) for i in result.indicators} == {("ip", "45.33.32.156"), ("sha256", SHA256)}
    assert result.skipped_non_ids == 1


def test_an_oversized_feed_fails_with_a_message():
    with pytest.raises(ioc.IocError, match="larger than"):
        ioc.parse_feed(b"x" * (ioc.MAX_FEED_BYTES + 1))


# --- matching -----------------------------------------------------------


def _row(ioc_type, value, source="feed"):
    indicator = ioc.Indicator(ioc_type, value)
    return {"ioc_id": indicator.ioc_id, "ioc_type": ioc_type, "value": value, "description": "", "source": source}


def test_a_domain_indicator_matches_its_subdomains_but_not_its_tld():
    matcher = ioc.Matcher([_row("domain", "evil.top")])

    assert list(matcher.matches(_event(1, domain="cdn.evil.top")))
    assert list(matcher.matches(_event(2, domain="evil.top")))
    assert not list(matcher.matches(_event(3, domain="notevil.top")))
    assert not list(matcher.matches(_event(4, domain="top")))


def test_network_url_hash_and_email_indicators_match():
    matcher = ioc.Matcher([
        _row("cidr", "45.33.32.0/24"),
        _row("url", "http://downloads.example.com/payload.bin"),
        _row("sha256", SHA256),
        _row("email", "attacker@evil.top"),
    ])

    assert list(matcher.matches(_event(1, dst_ip="45.33.32.200")))
    assert list(matcher.matches(_event(2, url="HTTP://Downloads.Example.com:80/payload.bin")))
    assert list(matcher.matches(_event(3, file_hash=SHA256.upper())))
    assert list(matcher.matches(_event(4, user="Attacker@Evil.Top")))
    assert not list(matcher.matches(_event(5, dst_ip="45.33.33.1")))


# --- in a case ----------------------------------------------------------


FEED = f"evil.top\n45.33.32.156\nhttp://downloads.example.com/payload.bin\n{SHA256}\n10.0.0.0/8\n"


def test_import_matches_once_per_indicator_not_once_per_event(case):
    """45.33.32.156 is in two events. Two identical rows would bury the one
    fact that matters: this indicator was seen."""
    _cases_dir, _case_id, case_dir = case
    with CaseStore(case_dir) as store:
        summary = ioc.import_into_case(store, case_dir, FEED.encode(), "campaign.txt")

    assert summary["added"] == 4
    assert summary["rejected_count"] == 1 and "too broad" in summary["rejected"][0]["reason"]
    assert summary["match_count"] == 4

    ip_match = next(d for d in summary["matches"] if "45.33.32.156" in d["description"])
    assert "2 event(s)" in ip_match["description"]
    assert ip_match["event_id"] == "EVT-EV-0001-000002", "the earliest event represents the match"


def test_matches_survive_the_next_analyze(case):
    """replace_detections rebuilds the table every run. A match written
    anywhere but inside scan_case would disappear here."""
    _cases_dir, _case_id, case_dir = case
    with CaseStore(case_dir) as store:
        ioc.import_into_case(store, case_dir, FEED.encode(), "campaign.txt")
        detections = scan_case(store)

    assert len([d for d in detections if d["rule_id"] == "IOC-MATCH"]) == 4


def test_reimporting_the_same_feed_adds_nothing(case):
    _cases_dir, _case_id, case_dir = case
    with CaseStore(case_dir) as store:
        ioc.import_into_case(store, case_dir, FEED.encode(), "campaign.txt")
        again = ioc.import_into_case(store, case_dir, FEED.encode(), "campaign.txt")

    assert again["added"] == 0
    assert again["already_present"] == 4
    assert again["total_indicators"] == 4


def test_clearing_indicators_removes_their_matches(case):
    _cases_dir, _case_id, case_dir = case
    with CaseStore(case_dir) as store:
        ioc.import_into_case(store, case_dir, FEED.encode(), "campaign.txt")
        removed = ioc.clear_from_case(store, case_dir)
        remaining = [d for d in store.list_detections() if d["rule_id"] == "IOC-MATCH"]

    assert removed == 4
    assert remaining == []


def test_the_custody_log_names_the_feed_by_its_hash(case):
    """"Matched against feed.csv" is unverifiable months later. A hash is not."""
    _cases_dir, _case_id, case_dir = case
    with CaseStore(case_dir) as store:
        ioc.import_into_case(store, case_dir, FEED.encode(), "campaign.txt")

    entry = next(e for e in audit.read_entries(case_dir) if e["action"] == audit.IOC_IMPORTED)
    assert entry["details"]["feed_sha256"] == ioc.feed_sha256(FEED.encode())
    assert entry["details"]["matches"] == 4
    assert audit.verify(case_dir)


def test_each_indicator_is_its_own_beat_in_the_story(case):
    """Grouped by rule, four different indicators would collapse into one
    beat showing one description and hiding three."""
    _cases_dir, _case_id, case_dir = case
    with CaseStore(case_dir) as store:
        ioc.import_into_case(store, case_dir, FEED.encode(), "campaign.txt")
        story = narrative_module.build(store)

    phases = dict((key, beats) for key, _title, beats in story.phases)
    assert len(phases["known-indicators"]) == 4
    assert story.phases[0][0] == "known-indicators", "intel matches lead the story"


def test_an_intel_match_alone_is_a_high_assessment_that_asks_for_confirmation(tmp_path):
    cases_dir = tmp_path / "cases"
    created = CaseManager(cases_dir).create(name="Only intel", investigator="analyst")
    case_dir = cases_dir / created.case_id
    events = [_event(1, src_ip="10.0.0.5", dst_ip="45.33.32.156", dst_port=443)]
    with CaseStore(case_dir) as store:
        store.replace_events_for_evidence("EV-0001", events)
        extract_and_store(store, events)
        ioc.import_into_case(store, case_dir, b"45.33.32.156\n", "feed.txt")
        story = narrative_module.build(store)

    assert story.severity == "high"
    assert "confirming" in story.assessment


# --- interfaces ---------------------------------------------------------


def test_web_import_lists_and_clears(case):
    from netforensicai.web.app import create_app

    cases_dir, case_id, _case_dir = case
    client = create_app(cases_dir).test_client()
    client.environ_base["HTTP_X_REQUESTED_WITH"] = "NetForensicAI"

    response = client.post(
        f"/api/cases/{case_id}/iocs",
        data={"file": (io.BytesIO(FEED.encode()), "campaign.txt")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 201, response.get_json()
    body = response.get_json()
    assert body["match_count"] == 4
    assert body["case"]["matched"] == 4

    listed = client.get(f"/api/cases/{case_id}/iocs").get_json()
    assert sum(1 for i in listed["indicators"] if i["matched"]) == 4

    cleared = client.delete(f"/api/cases/{case_id}/iocs", json={})
    assert cleared.get_json()["removed"] == 4


def test_web_import_refuses_a_request_without_the_csrf_header(case):
    from netforensicai.web.app import create_app

    cases_dir, case_id, _case_dir = case
    client = create_app(cases_dir).test_client()
    response = client.post(
        f"/api/cases/{case_id}/iocs",
        data={"file": (io.BytesIO(FEED.encode()), "campaign.txt")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 403


def test_cli_import_reports_matches_and_rejections(case, tmp_path):
    from netforensicai.cli import app

    cases_dir, case_id, _case_dir = case
    feed = tmp_path / "campaign.txt"
    feed.write_text(FEED, encoding="utf-8")

    result = CliRunner().invoke(app, ["ioc", "import", str(feed), "--case", case_id, "--cases-dir", str(cases_dir)])

    assert result.exit_code == 0, result.output
    assert "4 indicator(s) matched" in result.output
    assert "too broad" in result.output

    listed = CliRunner().invoke(app, ["ioc", "list", "--case", case_id, "--cases-dir", str(cases_dir)])
    assert "4 indicator(s), 4 matched" in listed.output


def test_a_comma_in_a_comment_does_not_turn_a_text_feed_into_csv():
    """Found running a realistic feed end to end, not by a unit test: the
    header comment "# Campaign feed, pasted from a vendor PDF" flipped
    detection to CSV, inline "# note" comments stayed attached to their
    values, and three of four good indicators were refused as
    unrecognisable. The feed looked broken; the importer was."""
    feed = (
        "# Campaign feed, pasted from a vendor PDF\n"
        "update-service.badcdn[.]top  # stager domain\n"
        "104.21.7[.]19  # drop host\n"
    )
    result = ioc.parse_feed(feed, "campaign.txt")

    assert result.feed_format == "text"
    assert {(i.ioc_type, i.value) for i in result.indicators} == {
        ("domain", "update-service.badcdn.top"),
        ("ip", "104.21.7.19"),
    }
    assert result.rejected == []


def test_headerless_csv_strips_an_inline_comment_from_the_indicator():
    result = ioc.parse_feed("evil.top # stager,phishing\n", "feed.csv")

    assert [(i.value, i.description) for i in result.indicators] == [("evil.top", "stager, phishing")]
