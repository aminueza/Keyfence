import json

import pytest

from keyfence.notice import NOTICES, add_notice

NOTICE = NOTICES["redact"]


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
    body = json.dumps({"anthropic_version": "bedrock-2023-05-31", "max_tokens": 10, "messages": []})
    out = load(add_notice(body, BEDROCK, path="/model/anthropic.claude-x/invoke"))
    assert out["system"] == NOTICE
    assert "role" not in json.dumps(out["messages"])


def test_anthropic_api_without_system_gets_one():
    body = json.dumps({"model": "claude", "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]})
    out = load(add_notice(body, "api.anthropic.com", path="/v1/messages"))
    assert out["system"] == NOTICE
    assert out["messages"] == [{"role": "user", "content": "hi"}]


BEDROCK = "bedrock-runtime.us-east-1.amazonaws.com"
VERTEX = "us-east5-aiplatform.googleapis.com"
CONVERSE_MESSAGES = [{"role": "user", "content": [{"text": "hi"}]}]


@pytest.mark.parametrize("path", ["/model/amazon.nova-pro-v1:0/converse", "/model/x/converse-stream?trace=1"])
def test_bedrock_converse_gets_a_text_block(path):
    body = json.dumps({"messages": CONVERSE_MESSAGES, "system": [{"text": "be brief"}]})
    out = load(add_notice(body, BEDROCK, path=path))
    assert out["system"] == [{"text": "be brief"}, {"text": NOTICE}]
    assert out["messages"] == CONVERSE_MESSAGES
    bare = load(add_notice(json.dumps({"messages": CONVERSE_MESSAGES}), BEDROCK, path=path))
    assert bare["system"] == [{"text": NOTICE}]


def test_bedrock_converse_with_a_system_that_is_not_a_list_is_left_alone():
    body = json.dumps({"messages": CONVERSE_MESSAGES, "system": "be brief"})
    assert add_notice(body, BEDROCK, path="/model/x/converse") == body


@pytest.mark.parametrize("body", [
    {"prompt": "hi", "max_gen_len": 10},
    {"messages": [{"role": "user", "content": [{"text": "hi"}]}], "inferenceConfig": {"maxTokens": 10}},
])
def test_a_bedrock_body_of_another_model_is_left_alone(body):
    raw = json.dumps(body)
    assert add_notice(raw, BEDROCK, path="/model/meta.llama3-70b-instruct-v1:0/invoke") == raw


def test_a_system_list_of_text_blocks_without_a_type_gets_the_same_shape():
    body = json.dumps({"messages": CONVERSE_MESSAGES, "system": [{"text": "be brief"}]})
    out = load(add_notice(body, BEDROCK, path="/model/amazon.nova-pro-v1:0/invoke"))
    assert out["system"] == [{"text": "be brief"}, {"text": NOTICE}]


@pytest.mark.parametrize("path", [
    "/v1/projects/p/locations/us-east5/publishers/anthropic/models/claude-x:rawPredict",
    "/v1/projects/p/locations/us-east5/publishers/anthropic/models/claude-x:streamRawPredict",
])
def test_vertex_anthropic_gets_system(path):
    body = json.dumps({"anthropic_version": "vertex-2023-10-16", "max_tokens": 10, "messages": []})
    out = load(add_notice(body, VERTEX, path=path))
    assert out["system"] == NOTICE and "systemInstruction" not in out
    no_version = load(add_notice(json.dumps({"max_tokens": 10, "messages": []}), VERTEX, path=path))
    assert no_version["system"] == NOTICE


@pytest.mark.parametrize("host, path", [
    (VERTEX, "/v1/projects/p/locations/us-east5/endpoints/openapi/chat/completions"),
    ("generativelanguage.googleapis.com", "/v1beta/openai/chat/completions"),
])
def test_openai_compatible_chat_on_google_gets_a_system_message(host, path):
    body = json.dumps({"model": "gemini", "messages": [{"role": "user", "content": "hi"}]})
    out = load(add_notice(body, host, path=path))
    assert out["messages"][0] == {"role": "system", "content": NOTICE}
    assert "systemInstruction" not in out


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


def test_a_lone_surrogate_escape_stays_an_escape_and_encodes_to_utf8():
    body = '{"system": "truncated \\ud83d emoji", "messages": []}'
    out = add_notice(body, "api.anthropic.com")
    out.encode("utf-8")
    assert "\\ud83d" in out
    assert load(out)["system"] == "truncated " + chr(0xD83D) + " emoji\n\n" + NOTICE


def test_a_lone_surrogate_does_not_escape_the_rest_of_the_unicode():
    body = '{"system": "ação 😀 \\ud83d", "messages": []}'
    out = add_notice(body, "api.anthropic.com")
    assert "ação 😀" in out
    assert out.encode("utf-8").decode("utf-8") == out


def test_each_mode_gets_a_notice_that_matches_what_happens_to_the_tokens():
    body = json.dumps({"system": "sys", "messages": []})
    redact = load(add_notice(body, "api.anthropic.com", "redact"))["system"]
    placeholder = load(add_notice(body, "api.anthropic.com", "placeholder"))["system"]
    assert "[REDACTED:<kind>]" in redact and "not restored" in redact and "<<SECRET_id>>" not in redact
    assert "<<SECRET_id>>" in placeholder and "restored automatically" in placeholder
    assert "[REDACTED" not in placeholder
