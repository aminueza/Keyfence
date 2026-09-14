import json

from keyfence.notice import NOTICE, add_notice


def load(body: str):
    return json.loads(body)


def test_anthropic_string_system_gets_notice_appended():
    body = json.dumps({"system": "You are Claude Code.", "messages": []})
    out = load(add_notice(body, "api.anthropic.com"))
    assert out["system"].startswith("You are Claude Code.\n\n")
    assert out["system"].endswith(NOTICE)


def test_anthropic_block_system_gets_new_block_at_the_end():
    blocks = [{"type": "text", "text": "sys", "cache_control": {"type": "ephemeral"}}]
    body = json.dumps({"system": blocks, "messages": []})
    out = load(add_notice(body, "api.anthropic.com"))
    assert out["system"][0] == blocks[0]
    assert out["system"][-1] == {"type": "text", "text": NOTICE}


def test_anthropic_without_system_gets_one():
    body = json.dumps({"model": "claude", "max_tokens": 10, "messages": []})
    out = load(add_notice(body, "bedrock-runtime.us-east-1.amazonaws.com"))
    assert out["system"] == NOTICE
    assert "role" not in json.dumps(out["messages"])


def test_openai_chat_without_a_system_message_gets_one_first():
    body = json.dumps({"model": "gpt", "messages": [{"role": "user", "content": "hi"}]})
    out = load(add_notice(body, "api.openai.com"))
    assert out["messages"][0] == {"role": "system", "content": NOTICE}
    assert out["messages"][1] == {"role": "user", "content": "hi"}


def test_openai_chat_extends_the_leading_system_message():
    body = json.dumps({"model": "gpt", "messages": [
        {"role": "system", "content": "be brief"}, {"role": "user", "content": "hi"}]})
    out = load(add_notice(body, "api.openai.com"))
    assert len(out["messages"]) == 2
    assert out["messages"][0] == {"role": "system", "content": f"be brief\n\n{NOTICE}"}
    assert out["messages"][1] == {"role": "user", "content": "hi"}


def test_openai_chat_extends_a_developer_message_and_keeps_content_blocks():
    body = json.dumps({"model": "gpt", "messages": [
        {"role": "developer", "content": [{"type": "text", "text": "sys"}]},
        {"role": "user", "content": "hi"}]})
    out = load(add_notice(body, "api.openai.com"))
    assert out["messages"][0]["role"] == "developer"
    assert out["messages"][0]["content"] == [{"type": "text", "text": "sys"}, {"type": "text", "text": NOTICE}]


def test_openai_chat_with_an_unusable_system_content_gets_its_own_message():
    body = json.dumps({"model": "gpt", "messages": [
        {"role": "system", "content": None}, {"role": "user", "content": "hi"}]})
    out = load(add_notice(body, "api.openai.com"))
    assert out["messages"][0] == {"role": "system", "content": NOTICE}
    assert len(out["messages"]) == 3


def test_openai_chat_with_no_messages_at_all():
    out = load(add_notice(json.dumps({"model": "gpt", "messages": []}), "api.openai.com"))
    assert out["messages"] == [{"role": "system", "content": NOTICE}]


def test_openai_responses_instructions_are_extended():
    body = json.dumps({"model": "gpt", "instructions": "be brief", "input": "hi"})
    out = load(add_notice(body, "api.openai.com"))
    assert out["instructions"] == f"be brief\n\n{NOTICE}"


def test_gemini_system_instruction():
    body = json.dumps({"contents": [], "systemInstruction": {"parts": [{"text": "sys"}]}})
    out = load(add_notice(body, "generativelanguage.googleapis.com"))
    assert out["systemInstruction"]["parts"] == [{"text": "sys"}, {"text": NOTICE}]
    bare = load(add_notice(json.dumps({"contents": []}), "generativelanguage.googleapis.com"))
    assert bare["systemInstruction"]["parts"] == [{"text": NOTICE}]


def test_gemini_with_malformed_parts_is_left_alone():
    body = json.dumps({"contents": [], "systemInstruction": {"parts": "oops"}})
    assert add_notice(body, "generativelanguage.googleapis.com") == body


def test_unknown_shapes_are_left_alone():
    assert add_notice("not json", "api.openai.com") == "not json"
    assert add_notice("[1, 2]", "api.openai.com") == "[1, 2]"
    body = json.dumps({"prompt": "hi"})
    assert add_notice(body, "api.example.com") == body


def test_unicode_survives_reserialisation():
    body = json.dumps({"system": "ação", "messages": []}, ensure_ascii=False)
    out = add_notice(body, "api.anthropic.com")
    assert "ação" in out
