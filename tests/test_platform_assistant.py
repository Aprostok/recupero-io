"""Unit tests for the AI Assistant — no live API call.

* pure helpers: address extraction, message normalization/clamping;
* grounding: screen_address monkeypatched to a fake result;
* answer(): a mock Anthropic client captures the request (verifies grounding is
  injected as an <SCREENING_DATA> system block) and returns canned content;
* router handler: disabled → 503, ValueError → 422, RuntimeError → 503.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from recupero.platform import assistant, router, store


# --------------------------------------------------------------------------- #
# pure helpers
# --------------------------------------------------------------------------- #

def test_extract_addresses_dedups_and_caps():
    a = "0x" + "a" * 40
    b = "0x" + "b" * 40
    c = "0x" + "c" * 40
    d = "0x" + "d" * 40
    text = f"send to {a} or {a} then {b} {c} {d}"
    out = assistant.extract_addresses(text)
    assert out == [a, b, c]           # dedup + cap at 3, order-stable


def test_extract_addresses_none():
    assert assistant.extract_addresses("no addresses here") == []


def test_normalize_messages_ok_and_clamps_length():
    long = "x" * (assistant.MAX_MSG_CHARS + 500)
    out = assistant.normalize_messages([{"role": "user", "content": long}])
    assert out[-1]["role"] == "user"
    assert len(out[-1]["content"]) == assistant.MAX_MSG_CHARS


def test_normalize_messages_caps_turn_count():
    msgs = [{"role": "user", "content": "hi"}] * (assistant.MAX_TURNS + 10)
    out = assistant.normalize_messages(msgs)
    assert len(out) == assistant.MAX_TURNS


@pytest.mark.parametrize(
    "bad",
    [
        [],
        [{"role": "system", "content": "x"}],
        [{"role": "user", "content": ""}],
        [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "yo"}],
    ],
)
def test_normalize_messages_rejects_invalid(bad):
    with pytest.raises(ValueError):
        assistant.normalize_messages(bad)


# --------------------------------------------------------------------------- #
# grounding
# --------------------------------------------------------------------------- #

class _FakeLabel:
    def __init__(self, name, category):
        self.name = name
        self.category = category


class _FakeScreen:
    def __init__(self, addr, verdict, score, labels, note):
        self.address = addr
        self.chain = "ethereum"
        self.risk_verdict = verdict
        self.risk_score = score
        self.labels = labels
        self.investigator_note = note


def test_build_grounding_screens_and_formats(monkeypatch):
    addr = "0x" + "a" * 40
    fake = _FakeScreen(addr, "sanctioned", 10, [_FakeLabel("Lazarus", "ofac_sanctioned")], "SANCTIONED — do not transact.")
    monkeypatch.setattr("recupero.screen.screener.screen_address", lambda a, **k: fake)
    block = assistant.build_grounding([addr], chain="ethereum")
    assert block and "sanctioned" in block
    assert "Lazarus" in block and "SANCTIONED" in block


def test_build_grounding_empty_is_none():
    assert assistant.build_grounding([]) is None


def test_build_grounding_skips_screen_failure(monkeypatch):
    def _boom(a, **k):
        raise RuntimeError("rpc down")
    monkeypatch.setattr("recupero.screen.screener.screen_address", _boom)
    assert assistant.build_grounding(["0x" + "a" * 40]) is None


# --------------------------------------------------------------------------- #
# answer() with a mock client
# --------------------------------------------------------------------------- #

class _Block:
    def __init__(self, text):
        self.text = text


class _Resp:
    def __init__(self, text):
        self.content = [_Block(text)]


class _MockClient:
    def __init__(self, text="Here is my answer."):
        self.captured = {}
        self._text = text

        class _Messages:
            def create(inner, **kwargs):  # noqa: N805
                self.captured = kwargs
                return _Resp(self._text)

        self.messages = _Messages()


def test_answer_injects_grounding_when_address_present(monkeypatch):
    addr = "0x" + "a" * 40
    fake = _FakeScreen(addr, "high", 7, [_FakeLabel("Drainer", "scam_drainer")], "HIGH-RISK.")
    monkeypatch.setattr("recupero.screen.screener.screen_address", lambda a, **k: fake)
    client = _MockClient("Do not send.")
    out = assistant.answer(
        [{"role": "user", "content": f"is {addr} safe?"}], client=client,
    )
    assert out["reply"] == "Do not send."
    assert out["grounded_addresses"] == [addr]
    # the screening facts were injected as a dedicated <SCREENING_DATA> block
    # (distinct from the base prompt, which merely mentions the marker in prose)
    systems = client.captured["system"]
    assert any(b["text"].startswith("<SCREENING_DATA>") for b in systems)


def test_answer_no_grounding_without_address():
    client = _MockClient("General safety tips…")
    out = assistant.answer([{"role": "user", "content": "how do drainers work?"}], client=client)
    assert out["grounded_addresses"] == []
    systems = client.captured["system"]
    assert not any(b["text"].startswith("<SCREENING_DATA>") for b in systems)


def test_answer_empty_reply_raises():
    client = _MockClient("")
    with pytest.raises(RuntimeError):
        assistant.answer([{"role": "user", "content": "hi"}], client=client)


def test_answer_bad_history_raises_valueerror():
    client = _MockClient("x")
    with pytest.raises(ValueError):
        assistant.answer([{"role": "assistant", "content": "hi"}], client=client)


# --------------------------------------------------------------------------- #
# router handler
# --------------------------------------------------------------------------- #

def _principal():
    return store.OrgContext(org_id="org1", plan="free", user_id="u1", role="member")


def test_assistant_chat_disabled_503(monkeypatch):
    monkeypatch.setattr(assistant, "is_enabled", lambda: False)
    with pytest.raises(HTTPException) as ei:
        router.assistant_chat(
            router.ChatIn(messages=[router.ChatMessage(role="user", content="hi")]),
            principal=_principal(), conn=object(),
        )
    assert ei.value.status_code == 503


def test_assistant_chat_ok(monkeypatch):
    monkeypatch.setattr(assistant, "is_enabled", lambda: True)
    monkeypatch.setattr(assistant, "answer",
                        lambda payload, **k: {"reply": "hello", "grounded_addresses": [], "model": "m"})
    monkeypatch.setattr(store, "record_usage", lambda *a, **k: None)
    out = router.assistant_chat(
        router.ChatIn(messages=[router.ChatMessage(role="user", content="hi")]),
        principal=_principal(), conn=object(),
    )
    assert out["reply"] == "hello"


def test_assistant_chat_runtime_error_503(monkeypatch):
    monkeypatch.setattr(assistant, "is_enabled", lambda: True)
    def _boom(payload, **k):
        raise RuntimeError("no key")
    monkeypatch.setattr(assistant, "answer", _boom)
    with pytest.raises(HTTPException) as ei:
        router.assistant_chat(
            router.ChatIn(messages=[router.ChatMessage(role="user", content="hi")]),
            principal=_principal(), conn=object(),
        )
    assert ei.value.status_code == 503
