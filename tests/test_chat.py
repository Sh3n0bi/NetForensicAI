"""Tests for the tool-calling chat loop.

No provider is ever called. The loop takes an injectable `call`, so every
test scripts exact model behaviour - which is the only way to test the
thing that actually matters here: what happens when a model cites
evidence no tool returned.
"""

import json

import pytest
from typer.testing import CliRunner

from netforensicai.cli import app as cli_app
from netforensicai.core import chat
from netforensicai.core.case import CaseManager
from netforensicai.core.correlation import correlate_case
from netforensicai.core.entities import extract_and_store
from netforensicai.core.evidence import EvidenceManager
from netforensicai.core.store import CaseStore

runner = CliRunner()


def _script(*responses):
    """A fake provider that returns each scripted response in turn, and
    records the prompts it was given."""
    calls = []

    def call(system_prompt, user_prompt):
        calls.append(user_prompt)
        if not responses:
            raise AssertionError("model called more times than the script provides")
        index = min(len(calls) - 1, len(responses) - 1)
        return responses[index]

    call.prompts = calls
    return call


@pytest.fixture
def case(tmp_path):
    """A case with two normalized events, no capture needed."""
    cases_dir = tmp_path / "cases"
    manager = CaseManager(cases_dir)
    created = manager.create(name="Chat case", investigator="analyst")
    case_dir = cases_dir / created.case_id

    source = tmp_path / "events.json"
    source.write_text(
        json.dumps(
            [
                {
                    "timestamp": "2026-08-27T09:00:00Z",
                    "type": "authentication",
                    "user": "jdoe",
                    "src_ip": "192.168.1.10",
                },
                {
                    "timestamp": "2026-08-27T09:00:30Z",
                    "type": "network_connection",
                    "src_ip": "192.168.1.10",
                    "dst_ip": "203.0.113.7",
                    "dst_port": 4444,
                },
            ]
        ),
        encoding="utf-8",
    )
    evidence = EvidenceManager(case_dir).add(source, case_id=created.case_id)
    manager.register_evidence(created.case_id, evidence.evidence_id)

    from netforensicai.parsers.generic import JsonParser

    events = JsonParser().parse(
        EvidenceManager(case_dir).stored_file_path(evidence.evidence_id),
        evidence_id=evidence.evidence_id,
    )
    with CaseStore(case_dir) as store:
        store.replace_events_for_evidence(evidence.evidence_id, events)
        extract_and_store(store, events)
        correlate_case(store)

    return cases_dir, created, case_dir, evidence, events


# --- The ledger ---------------------------------------------------------


def test_the_ledger_only_admits_what_was_recorded():
    ledger = chat.Ledger()
    ledger.record("event", "EV-0001", "EVT-0001")

    assert ledger.contains(chat.Citation(kind="event", evidence_id="EV-0001", reference="EVT-0001"))
    assert not ledger.contains(chat.Citation(kind="event", evidence_id="EV-0001", reference="EVT-0002"))
    # Right reference, wrong evidence item, and right reference under the
    # wrong kind both fail: a citation is the whole triple.
    assert not ledger.contains(chat.Citation(kind="event", evidence_id="EV-0002", reference="EVT-0001"))
    assert not ledger.contains(chat.Citation(kind="frame", evidence_id="EV-0001", reference="EVT-0001"))


def test_the_ledger_normalizes_numeric_references():
    """Frame and stream numbers arrive as ints from tools and as strings
    from the model; they have to compare equal."""
    ledger = chat.Ledger()
    ledger.record("frame", "EV-0001", 42)

    assert ledger.contains(chat.Citation(kind="frame", evidence_id="EV-0001", reference="42"))


def test_the_ledger_ignores_incomplete_facts():
    ledger = chat.Ledger()
    ledger.record("event", "EV-0001", None)
    ledger.record("event", None, "EVT-0001")

    assert ledger.is_empty()


# --- The loop -----------------------------------------------------------


def test_a_question_answered_from_retrieved_events(case):
    _cases_dir, _created, case_dir, evidence, events = case
    event_id = events[0].event_id

    call = _script(
        {"action": "tool", "tool": "search_events", "arguments": {"event_type": "authentication"}},
        {
            "action": "answer",
            "evidence_sufficient": True,
            "answer": "An authentication by jdoe from 192.168.1.10 may be the starting point.",
            "citations": [
                {"kind": "event", "evidence_id": evidence.evidence_id, "reference": event_id}
            ],
        },
    )

    result = chat.ask("What happened?", case_dir, call=call)

    assert result.evidence_sufficient
    assert "jdoe" in result.answer
    assert len(result.citations) == 1
    assert [step.tool for step in result.steps] == ["search_events"]


def test_tool_results_are_put_in_front_of_the_model(case):
    """The model must be reasoning over real retrieved rows, not over its
    own recollection of the question."""
    _cases_dir, _created, case_dir, evidence, events = case

    call = _script(
        {"action": "tool", "tool": "search_events", "arguments": {}},
        {"action": "answer", "evidence_sufficient": False, "answer": "Not enough.", "citations": []},
    )
    chat.ask("What happened?", case_dir, call=call)

    second_prompt = call.prompts[1]
    assert "You called search_events" in second_prompt
    assert events[0].event_id in second_prompt


def test_an_answer_citing_evidence_no_tool_returned_is_refused(case):
    """The property the whole module exists for. The model retrieves one
    event and then cites a different one - an invented reference - twice.
    Nothing is shown."""
    _cases_dir, _created, case_dir, evidence, _events = case

    fabricated = {
        "action": "answer",
        "evidence_sufficient": True,
        "answer": "The attacker exfiltrated data.",
        "citations": [
            {"kind": "event", "evidence_id": evidence.evidence_id, "reference": "EVT-DOES-NOT-EXIST"}
        ],
    }
    call = _script(
        {"action": "tool", "tool": "search_events", "arguments": {}},
        fabricated,
        fabricated,
    )

    with pytest.raises(chat.ChatError) as excinfo:
        chat.ask("What happened?", case_dir, call=call)

    assert "EVT-DOES-NOT-EXIST" in str(excinfo.value)
    assert "refused" in str(excinfo.value).lower()


def test_an_unverifiable_citation_gets_exactly_one_correction_pass(case):
    """A model that cited something adjacent to a real result should be
    able to fix it; the retry is what draws the line between a slip and an
    invented finding."""
    _cases_dir, _created, case_dir, evidence, events = case
    real_event = events[0].event_id

    call = _script(
        {"action": "tool", "tool": "search_events", "arguments": {}},
        {
            "action": "answer",
            "evidence_sufficient": True,
            "answer": "First attempt.",
            "citations": [{"kind": "event", "evidence_id": evidence.evidence_id, "reference": "EVT-WRONG"}],
        },
        {
            "action": "answer",
            "evidence_sufficient": True,
            "answer": "Corrected answer.",
            "citations": [{"kind": "event", "evidence_id": evidence.evidence_id, "reference": real_event}],
        },
    )

    result = chat.ask("What happened?", case_dir, call=call)

    assert result.answer == "Corrected answer."
    # The correction prompt has to name what failed, or the model cannot fix it.
    assert "EVT-WRONG" in call.prompts[-1]


def test_an_answer_with_no_citations_is_allowed_when_evidence_is_insufficient(case):
    """Refusing to answer is a correct outcome, and must not require
    citations to prove it."""
    _cases_dir, _created, case_dir, _evidence, _events = case

    call = _script(
        {
            "action": "answer",
            "evidence_sufficient": False,
            "answer": "The case holds no DNS evidence, so this cannot be determined.",
            "citations": [],
        }
    )

    result = chat.ask("Was there DNS tunnelling?", case_dir, call=call)

    assert result.evidence_sufficient is False
    assert result.citations == []


def test_a_failing_tool_is_reported_back_instead_of_killing_the_question(case):
    """A bad argument is something the model can correct on the next step."""
    _cases_dir, _created, case_dir, _evidence, _events = case

    call = _script(
        {"action": "tool", "tool": "follow_stream", "arguments": {"stream": 0}},
        {"action": "answer", "evidence_sufficient": False, "answer": "No captures here.", "citations": []},
    )

    result = chat.ask("Follow the first stream", case_dir, call=call)

    assert result.steps[0].error, "the tool error should have been recorded"
    assert "Error:" in call.prompts[1]


def test_an_unknown_tool_is_reported_back(case):
    _cases_dir, _created, case_dir, _evidence, _events = case

    call = _script(
        {"action": "tool", "tool": "run_shell", "arguments": {"cmd": "rm -rf /"}},
        {"action": "answer", "evidence_sufficient": False, "answer": "Cannot.", "citations": []},
    )

    result = chat.ask("Delete everything", case_dir, call=call)

    assert "Unknown tool" in result.steps[0].error


def test_unexpected_tool_arguments_are_dropped_rather_than_failing(case):
    _cases_dir, _created, case_dir, _evidence, _events = case

    call = _script(
        {"action": "tool", "tool": "search_events", "arguments": {"event_type": "authentication", "colour": "red"}},
        {"action": "answer", "evidence_sufficient": False, "answer": "ok", "citations": []},
    )

    result = chat.ask("What happened?", case_dir, call=call)

    assert result.steps[0].error is None
    assert result.steps[0].rows >= 1


def test_a_model_that_never_answers_is_stopped(case):
    _cases_dir, _created, case_dir, _evidence, _events = case

    call = _script({"action": "tool", "tool": "list_evidence", "arguments": {}})

    with pytest.raises(chat.ChatError, match="No answer after"):
        chat.ask("What happened?", case_dir, call=call, max_steps=3)


def test_the_last_turn_tells_the_model_to_answer(case):
    _cases_dir, _created, case_dir, _evidence, _events = case

    call = _script({"action": "tool", "tool": "list_evidence", "arguments": {}})
    with pytest.raises(chat.ChatError):
        chat.ask("What happened?", case_dir, call=call, max_steps=2)

    assert "LAST turn" in call.prompts[-1]


def test_a_malformed_answer_is_rejected(case):
    _cases_dir, _created, case_dir, _evidence, _events = case

    call = _script({"action": "answer", "answer": "no evidence_sufficient field"})

    with pytest.raises(chat.ChatError, match="expected format"):
        chat.ask("What happened?", case_dir, call=call)


def test_a_non_object_response_is_rejected(case):
    _cases_dir, _created, case_dir, _evidence, _events = case

    def call(system_prompt, user_prompt):
        return "just a string"

    with pytest.raises(chat.ChatError, match="not a JSON object"):
        chat.ask("What happened?", case_dir, call=call)


def test_a_provider_failure_is_reported_as_one(case):
    _cases_dir, _created, case_dir, _evidence, _events = case

    def call(system_prompt, user_prompt):
        raise RuntimeError("connection refused")

    with pytest.raises(chat.ChatError, match="AI provider failed"):
        chat.ask("What happened?", case_dir, call=call)


def test_an_empty_question_is_rejected(case):
    _cases_dir, _created, case_dir, _evidence, _events = case

    with pytest.raises(chat.ChatError, match="empty"):
        chat.ask("   ", case_dir, call=_script())


# --- Tools --------------------------------------------------------------


def test_every_advertised_tool_exists(case):
    """The catalogue is what the model is told it can call; a name in it
    with no method behind it wastes a step and confuses the model."""
    _cases_dir, _created, case_dir, _evidence, _events = case
    tools = chat.CaseTools(case_dir, chat.Ledger())

    for name in chat.TOOL_SPECS:
        assert callable(getattr(tools, name, None)), name


def test_tools_record_what_they_return(case):
    _cases_dir, _created, case_dir, evidence, events = case
    ledger = chat.Ledger()
    tools = chat.CaseTools(case_dir, ledger)

    rows = tools.search_events()

    assert rows
    for row in rows:
        assert ledger.contains(
            chat.Citation(kind="event", evidence_id=row["evidence_id"], reference=row["event_id"])
        )


def test_tools_do_not_write_to_the_case(case):
    """Answering a question is not an action taken on evidence."""
    from netforensicai.core import audit
    from netforensicai.core.finding import FindingManager

    _cases_dir, _created, case_dir, _evidence, _events = case
    before = len(audit.read_entries(case_dir))

    tools = chat.CaseTools(case_dir, chat.Ledger())
    tools.list_evidence()
    tools.search_events()
    tools.list_detections()
    tools.list_entities()

    assert len(audit.read_entries(case_dir)) == before
    assert FindingManager(case_dir).list() == []


def test_search_events_filters_are_the_ones_the_timeline_implements():
    """Advertising a filter the timeline does not implement would return
    unfiltered rows the model then reasons about as though filtered."""
    import inspect

    from netforensicai.core.timeline import filter_timeline

    supported = set(inspect.signature(filter_timeline).parameters)
    offered = set(inspect.signature(chat.CaseTools.search_events).parameters) - {"self", "limit"}

    assert offered <= supported, offered - supported


# --- The loop driving real tools against real evidence ------------------


@pytest.mark.skipif(
    not __import__("netforensicai.integrations.wireshark", fromlist=["x"]).available(),
    reason="Wireshark/tshark is not installed on this machine",
)
def test_the_loop_finds_a_flag_in_a_real_capture_and_cites_the_frame(tmp_path):
    """Everything except the provider HTTP call, against real evidence.

    The scripted model behaves the way a real one should: search the
    packets, follow the conversation the hit points at, then answer citing
    the frame it actually saw. What this proves is that the tools work
    through the loop and that the ledger accepts a citation derived from
    genuine retrieval - the isolated tool tests cannot show either.
    """
    from scapy.all import IP, TCP, Ether, Raw, wrpcap

    flag = "flag{chat_retrieved_this}"
    client, server = "10.0.0.5", "93.184.216.34"

    def tcp(src, dst, sport, dport, flags, seq, ack, payload=b"", offset=0.0):
        pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
        if payload:
            pkt = pkt / Raw(load=payload)
        pkt.time = 1_700_000_000.0 + offset
        return pkt

    request = b"GET /flag HTTP/1.1\r\nHost: ctf.example.com\r\n\r\n"
    body = flag.encode()
    response = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body
    capture = tmp_path / "flag.pcap"
    wrpcap(
        str(capture),
        [
            tcp(client, server, 44000, 80, "S", 1000, 0, offset=0.1),
            tcp(server, client, 80, 44000, "SA", 5000, 1001, offset=0.2),
            tcp(client, server, 44000, 80, "A", 1001, 5001, offset=0.3),
            tcp(client, server, 44000, 80, "PA", 1001, 5001, request, offset=0.4),
            tcp(server, client, 80, 44000, "PA", 5001, 1001 + len(request), response, offset=0.5),
        ],
    )

    cases_dir = tmp_path / "cases"
    manager = CaseManager(cases_dir)
    created = manager.create(name="CTF", investigator="player")
    case_dir = cases_dir / created.case_id
    evidence = EvidenceManager(case_dir).add(capture, case_id=created.case_id)
    manager.register_evidence(created.case_id, evidence.evidence_id)

    seen = {}

    def call(system_prompt, user_prompt):
        seen["last"] = user_prompt
        if "You called search_packets" not in user_prompt:
            return {
                "action": "tool",
                "tool": "search_packets",
                "arguments": {"pattern": "flag{", "mode": "text"},
            }
        if "You called follow_stream" not in user_prompt:
            return {"action": "tool", "tool": "follow_stream", "arguments": {"stream": 0}}
        # Cite the frame the search actually returned.
        frame = json.loads(
            user_prompt.split("Result:\n")[1].split("\n")[0]
        )[0]["frame"]
        return {
            "action": "answer",
            "evidence_sufficient": True,
            "answer": f"The response body contains {flag}.",
            "citations": [
                {"kind": "frame", "evidence_id": evidence.evidence_id, "reference": str(frame)}
            ],
        }

    result = chat.ask("Is there a flag in this capture?", case_dir, call=call)

    assert flag in result.answer
    assert [step.tool for step in result.steps] == ["search_packets", "follow_stream"]
    assert all(step.error is None for step in result.steps)
    assert result.citations[0].kind == "frame"
    # The reassembled conversation reached the model, not just the hit list.
    assert flag in seen["last"]


# --- CLI ----------------------------------------------------------------


def test_cli_chat_prints_the_answer_and_its_citations(case, monkeypatch):
    cases_dir, created, _case_dir, evidence, events = case
    event_id = events[0].event_id

    def fake_ask(question, case_dir, **kwargs):
        return chat.ChatResult(
            question=question,
            answer="Something may have happened.",
            evidence_sufficient=True,
            citations=[chat.Citation(kind="event", evidence_id=evidence.evidence_id, reference=event_id)],
            steps=[chat.ToolCall(tool="search_events", arguments={}, summary="2 result(s)", rows=2)],
        )

    monkeypatch.setattr(chat, "ask", fake_ask)

    result = runner.invoke(
        cli_app, ["chat", "--case", created.case_id, "What happened?", "--cases-dir", str(cases_dir)]
    )

    assert result.exit_code == 0, result.output
    assert "Something may have happened." in result.output
    assert event_id in result.output
    assert "search_events" in result.output


def test_cli_option_default_matches_the_module():
    import netforensicai.cli as cli

    assert cli.CHAT_DEFAULT_MAX_STEPS == chat.MAX_STEPS


# --- Web API ------------------------------------------------------------


def test_web_chat_returns_the_answer_and_citations(case, monkeypatch):
    from netforensicai.web.app import create_app

    cases_dir, created, _case_dir, evidence, events = case

    def fake_ask(question, case_dir, **kwargs):
        return chat.ChatResult(
            question=question,
            answer="Possible beaconing.",
            evidence_sufficient=True,
            citations=[
                chat.Citation(kind="event", evidence_id=evidence.evidence_id, reference=events[1].event_id)
            ],
            steps=[chat.ToolCall(tool="search_events", arguments={}, summary="2 result(s)", rows=2)],
        )

    monkeypatch.setattr(chat, "ask", fake_ask)
    client = create_app(cases_dir).test_client()
    client.environ_base["HTTP_X_REQUESTED_WITH"] = "NetForensicAI"

    response = client.post(f"/api/cases/{created.case_id}/chat", json={"question": "What happened?"})

    assert response.status_code == 200, response.get_json()
    payload = response.get_json()
    assert payload["answer"] == "Possible beaconing."
    assert payload["citations"][0]["reference"] == events[1].event_id
    assert payload["steps"][0]["tool"] == "search_events"


def test_web_chat_surfaces_a_refusal_as_an_error_not_an_answer(case, monkeypatch):
    """A refused answer must never reach the browser as content."""
    from netforensicai.web.app import create_app

    cases_dir, created, _case_dir, _evidence, _events = case

    def fake_ask(question, case_dir, **kwargs):
        raise chat.ChatError("Answer refused: it cited evidence no tool returned.")

    monkeypatch.setattr(chat, "ask", fake_ask)
    client = create_app(cases_dir).test_client()
    client.environ_base["HTTP_X_REQUESTED_WITH"] = "NetForensicAI"

    response = client.post(f"/api/cases/{created.case_id}/chat", json={"question": "What happened?"})

    assert response.status_code == 502
    assert "refused" in response.get_json()["error"].lower()


def test_web_chat_requires_a_question(case):
    from netforensicai.web.app import create_app

    cases_dir, created, _case_dir, _evidence, _events = case
    client = create_app(cases_dir).test_client()
    client.environ_base["HTTP_X_REQUESTED_WITH"] = "NetForensicAI"

    response = client.post(f"/api/cases/{created.case_id}/chat", json={})

    assert response.status_code == 400


def test_cli_chat_reports_a_refusal_as_an_error(case, monkeypatch):
    cases_dir, created, _case_dir, _evidence, _events = case

    def fake_ask(question, case_dir, **kwargs):
        raise chat.ChatError("Answer refused: it cited evidence no tool returned.")

    monkeypatch.setattr(chat, "ask", fake_ask)

    result = runner.invoke(
        cli_app, ["chat", "--case", created.case_id, "What happened?", "--cases-dir", str(cases_dir)]
    )

    assert result.exit_code == 1
    assert "refused" in result.output.lower()
