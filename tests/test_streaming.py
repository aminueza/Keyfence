import json

import pytest

from keyfence.streaming import Event, SSERestorer, partial_suffix, restore, restore_json

KEY = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
MAPPING = {"<<SECRET_1>>": KEY, "<<SECRET_12>>": "second-secret-value"}


def anthropic_event(text: str) -> str:
    payload = {"type": "content_block_delta", "index": 0,
               "delta": {"type": "text_delta", "text": text}}
    return f"event: content_block_delta\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"


def openai_event(text: str) -> str:
    payload = {"choices": [{"index": 0, "delta": {"content": text}}]}
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


def texts(output: bytes) -> list[str]:
    found = []
    for block in output.decode().split("\n\n"):
        for line in block.split("\n"):
            if line.startswith("data:"):
                try:
                    obj = json.loads(line[5:])
                except ValueError:
                    continue
                if "delta" in obj and "text" in obj["delta"]:
                    found.append(obj["delta"]["text"])
                elif "choices" in obj:
                    found.append(obj["choices"][0]["delta"]["content"])
    return found


def test_restore_replaces_every_token():
    assert restore("a <<SECRET_1>> b <<SECRET_1>>", MAPPING) == f"a {KEY} b {KEY}"
    assert restore("untouched", MAPPING) == "untouched"


def test_partial_suffix():
    tokens = tuple(MAPPING)
    assert partial_suffix("text <<SEC", tokens, 13) == "<<SEC"
    assert partial_suffix("text <", tokens, 13) == "<"
    assert partial_suffix("text <<SECRET_1", tokens, 13) == "<<SECRET_1"
    assert partial_suffix("text <<SECRET_1>>", tokens, 13) == ""
    assert partial_suffix("no angle here", tokens, 13) == ""
    assert partial_suffix("x <y", tokens, 13) == ""


def test_event_roundtrip_untouched():
    raw = "event: ping\ndata: {\"type\":\"ping\"}\n\n"
    assert Event(raw).render() == raw


def test_event_get_set_render():
    ev = Event(anthropic_event("hello"))
    assert ev.get(("delta", "text")) == "hello"
    ev.set(("delta", "text"), "bye")
    assert json.loads(ev.render().split("\n")[1][5:])["delta"]["text"] == "bye"


def test_event_with_non_json_data():
    ev = Event("data: [DONE]\n\n")
    assert ev.obj is None
    assert ev.render() == "data: [DONE]\n\n"


def chat_chunk(content: str, token: str | None = None) -> str:
    choice = {"index": 0, "delta": {"content": content}}
    if token is not None:
        choice["logprobs"] = {"content": [{"token": token, "logprob": -0.1}]}
    return f"data: {json.dumps({'choices': [choice]}, ensure_ascii=False)}\n\n"


def logprobs_tokens(output: bytes) -> list[str]:
    found = []
    for block in output.decode().split("\n\n"):
        for line in block.split("\n"):
            if line.startswith("data:"):
                obj = json.loads(line[5:])
                entry = obj.get("choices", [{}])[0].get("logprobs")
                if entry:
                    found.extend(token["token"] for token in entry["content"])
    return found


def test_a_logprobs_token_that_starts_like_a_placeholder_stays_in_its_chunk():
    r = SSERestorer(MAPPING)
    out = r.feed(chat_chunk("a", "<").encode()) + r.feed(chat_chunk("b", "div").encode()) + r.feed(b"")
    assert texts(out) == ["a", "b"]
    assert logprobs_tokens(out) == ["<", "div"]


def test_a_whole_placeholder_in_a_logprobs_token_is_restored():
    r = SSERestorer(MAPPING)
    out = r.feed(chat_chunk("x", "<<SECRET_1>>").encode()) + r.feed(b"")
    assert logprobs_tokens(out) == [KEY]


def test_a_placeholder_split_across_chunks_is_still_restored_in_the_content():
    r = SSERestorer(MAPPING)
    out = (r.feed(chat_chunk("use <<SEC", "<").encode()) + r.feed(chat_chunk("RET_1>> ok", "").encode())
           + r.feed(b""))
    assert "".join(texts(out)) == f"use {KEY} ok"


def test_whole_placeholder_in_one_event():
    r = SSERestorer(MAPPING)
    out = r.feed(anthropic_event("use <<SECRET_1>> now").encode()) + r.feed(b"")
    assert texts(out) == [f"use {KEY} now"]


def test_placeholder_split_across_two_events_is_held_then_restored():
    r = SSERestorer(MAPPING)
    first = r.feed(anthropic_event("use the key <<SEC").encode())
    assert first == b""
    second = r.feed(anthropic_event("RET_1>> ok").encode())
    assert texts(second) == ["use the key ", f"{KEY} ok"]
    assert r.feed(b"") == b""


def test_placeholder_split_across_three_events():
    r = SSERestorer(MAPPING)
    stream = anthropic_event("<") + anthropic_event("<SECRET_") + anthropic_event("1>> done")
    out = r.feed(stream.encode()) + r.feed(b"")
    assert "".join(texts(out)) == f"{KEY} done"


def test_longer_token_is_preferred_when_ambiguous():
    r = SSERestorer(MAPPING)
    out = r.feed((anthropic_event("<<SECRET_1") + anthropic_event("2>>")).encode()) + r.feed(b"")
    assert "".join(texts(out)) == "second-secret-value"


def test_openai_format():
    r = SSERestorer(MAPPING)
    stream = openai_event("key: <<SEC") + openai_event("RET_1>>") + "data: [DONE]\n\n"
    out = r.feed(stream.encode()) + r.feed(b"")
    assert "".join(texts(out)) == f"key: {KEY}"
    assert out.endswith(b"data: [DONE]\n\n")


def test_other_events_are_queued_behind_a_hold_and_preserved():
    r = SSERestorer(MAPPING)
    ping = "event: ping\ndata: {\"type\":\"ping\"}\n\n"
    first = r.feed((anthropic_event("<<SEC") + ping).encode())
    assert first == b""
    out = first + r.feed(anthropic_event("RET_1>>").encode())
    assert ping.encode() in out
    assert out.index(b"ping") < out.rindex(b"content_block_delta")


def test_unresolved_partial_is_flushed_unchanged_at_end():
    r = SSERestorer(MAPPING)
    out = r.feed(anthropic_event("ends with <<SEC").encode())
    assert out == b""
    assert texts(r.feed(b"")) == ["ends with <<SEC"]


def test_chunk_boundaries_inside_events():
    r = SSERestorer(MAPPING)
    stream = anthropic_event("use <<SECRET_1>> now").encode()
    out = b"".join(r.feed(stream[i:i + 7]) for i in range(0, len(stream), 7)) + r.feed(b"")
    assert texts(out) == [f"use {KEY} now"]


def test_multibyte_characters_split_across_chunks():
    r = SSERestorer(MAPPING)
    stream = anthropic_event("ação <<SECRET_1>> ✓").encode()
    cut = stream.index("ção".encode()) + 1
    out = r.feed(stream[:cut]) + r.feed(stream[cut:]) + r.feed(b"")
    assert texts(out) == [f"ação {KEY} ✓"]


def test_crlf_event_boundaries():
    r = SSERestorer(MAPPING)
    stream = anthropic_event("use <<SECRET_1>>").replace("\n\n", "\r\n\r\n").encode()
    out = r.feed(stream) + r.feed(b"")
    assert KEY.encode() in out


def test_trailing_event_without_terminator_is_processed_at_end():
    r = SSERestorer(MAPPING)
    out = r.feed(anthropic_event("use <<SECRET_1>>").rstrip("\n").encode()) + r.feed(b"")
    assert KEY.encode() in out


def test_non_object_json_is_passed_through():
    r = SSERestorer(MAPPING)
    raw = "data: 42\n\n"
    assert r.feed(raw.encode()) + r.feed(b"") == raw.encode()


def test_lists_in_payload_are_walked():
    r = SSERestorer(MAPPING)
    payload = {"candidates": [{"content": {"parts": [{"text": "<<SECRET_1>>"}]}}]}
    out = r.feed(f"data: {json.dumps(payload)}\n\n".encode()) + r.feed(b"")
    assert json.loads(out.decode()[5:].strip())["candidates"][0]["content"]["parts"][0]["text"] == KEY


def test_stream_never_yields_an_empty_chunk():
    restorer = SSERestorer(MAPPING)
    half = openai_event("<<SECRET")
    assert restorer.stream(half.encode()) == []
    tail = openai_event("_1>> done")
    assert restorer.stream(tail[:20].encode()) == []
    out = restorer.stream(tail[20:].encode())
    assert out and all(chunk for chunk in out)
    assert KEY in b"".join(out).decode()
    assert restorer.stream(b"") == []


def test_stream_returns_the_same_bytes_as_feed():
    events = (openai_event("a <<SECRET_1>> b") + openai_event("c")).encode()
    assert b"".join(SSERestorer(MAPPING).stream(events)) == SSERestorer(MAPPING).feed(events)


NESTED_VALUE = 'line1\nsays "hi"\tend'


def test_restore_escapes_when_writing_into_raw_json_text():
    text = json.dumps({"text": "<<SECRET_1>>"})
    restored = restore(text, {"<<SECRET_1>>": NESTED_VALUE}, escape=1)
    assert json.loads(restored)["text"] == NESTED_VALUE


def test_nested_json_field_gets_one_more_level_of_escaping():
    restorer = SSERestorer({"<<SECRET_1>>": NESTED_VALUE})
    payload = {"type": "content_block_delta", "index": 0,
               "delta": {"type": "input_json_delta",
                         "partial_json": json.dumps({"key": "<<SECRET_1>>"})}}
    raw = f"data: {json.dumps(payload)}\n\n".encode()
    out = (restorer.feed(raw) + restorer.feed(b"")).decode()
    event = json.loads(out.split("data: ", 1)[1])
    assert json.loads(event["delta"]["partial_json"]) == {"key": NESTED_VALUE}


def test_responses_api_delta_field_with_json_string_parses():
    PEM = ("-----BEGIN PRIVATE KEY-----\n"
           "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDtest\n"
           "-----END PRIVATE KEY-----")
    mapping = {"<<SECRET_1>>": PEM}
    restorer = SSERestorer(mapping)

    payload = {
        "type": "response.function_call_arguments.delta",
        "delta": json.dumps({"key": "<<SECRET_1>>"})
    }
    raw = f"data: {json.dumps(payload)}\n\n".encode()
    out = (restorer.feed(raw) + restorer.feed(b"")).decode()
    event = json.loads(out.split("data: ", 1)[1])
    inner = json.loads(event["delta"])
    assert inner == {"key": PEM}


def test_buffered_arguments_array_with_json_string_no_extra_escaping():
    PEM = ("-----BEGIN PRIVATE KEY-----\n"
           "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDtest\n"
           "-----END PRIVATE KEY-----")
    mapping = {"<<SECRET_1>>": PEM}
    nested = json.dumps({"key": "<<SECRET_1>>"})
    body = json.dumps({"arguments": [nested]})
    restored = restore_json(body, mapping)
    parsed = json.loads(restored)
    inner = json.loads(parsed["arguments"][0])
    assert inner == {"key": PEM}


def test_buffered_arguments_array_with_plain_string_gets_one_level():
    PEM = ("-----BEGIN PRIVATE KEY-----\n"
           "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDtest\n"
           "-----END PRIVATE KEY-----")
    mapping = {"<<SECRET_1>>": PEM}
    body = json.dumps({"arguments": ["<<SECRET_1>>"]})
    restored = restore_json(body, mapping)
    parsed = json.loads(restored)
    assert parsed["arguments"][0] == PEM


def test_restore_json_escapes_an_arguments_delta_twice_and_a_text_delta_once():
    mapping = {"<<SECRET_1>>": 'pa"ss\\w'}
    arguments = json.dumps({"type": "response.function_call_arguments.delta", "delta": '<<SECRET_1>>"}'})
    restored = json.loads(restore_json(arguments, mapping))["delta"]
    assert json.loads('{"cmd":"' + restored) == {"cmd": 'pa"ss\\w'}
    text = json.dumps({"type": "response.output_text.delta", "delta": "<<SECRET_1>>"})
    assert json.loads(restore_json(text, mapping))["delta"] == 'pa"ss\\w'
    quoting = json.dumps({"type": "response.output_text.delta", "delta": "response.function_call_arguments.delta <<SECRET_1>>"})
    assert json.loads(restore_json(quoting, mapping))["delta"] == 'response.function_call_arguments.delta pa"ss\\w'


def test_restore_json_restores_object_keys():
    mapping = {"<<SECRET_1>>": "actual-secret"}
    body = '{"<<SECRET_1>>": "value"}'
    restored = restore_json(body, mapping)
    parsed = json.loads(restored)
    assert "actual-secret" in parsed
    assert parsed["actual-secret"] == "value"


def test_two_text_blocks_first_ends_with_lt_does_not_move_to_second():
    r = SSERestorer(MAPPING)

    block0_start = 'event: content_block_start\ndata: {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}\n\n'
    block0_delta = 'event: content_block_delta\ndata: {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "hello <"}}\n\n'
    block0_stop = 'event: content_block_stop\ndata: {"type": "content_block_stop", "index": 0}\n\n'

    block1_start = 'event: content_block_start\ndata: {"type": "content_block_start", "index": 1, "content_block": {"type": "text", "text": ""}}\n\n'
    block1_delta = 'event: content_block_delta\ndata: {"type": "content_block_delta", "index": 1, "delta": {"type": "text_delta", "text": "world"}}\n\n'
    block1_stop = 'event: content_block_stop\ndata: {"type": "content_block_stop", "index": 1}\n\n'

    stream = block0_start + block0_delta + block0_stop + block1_start + block1_delta + block1_stop

    out = r.feed(stream.encode()) + r.feed(b"")
    result_texts = texts(out)

    assert result_texts == ["hello <", "world"]


def test_events_after_block_stop_emitted_without_waiting_for_next_block():
    r = SSERestorer(MAPPING)

    block0_start = 'event: content_block_start\ndata: {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}\n\n'
    block0_delta = 'event: content_block_delta\ndata: {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "hello <"}}\n\n'
    block0_stop = 'event: content_block_stop\ndata: {"type": "content_block_stop", "index": 0}\n\n'

    stream_part1 = block0_start + block0_delta + block0_stop
    out1 = r.feed(stream_part1.encode())

    assert texts(out1) == ["hello <"]

    block1_start = 'event: content_block_start\ndata: {"type": "content_block_start", "index": 1, "content_block": {"type": "text", "text": ""}}\n\n'
    block1_delta = 'event: content_block_delta\ndata: {"type": "content_block_delta", "index": 1, "delta": {"type": "text_delta", "text": "world"}}\n\n'
    block1_stop = 'event: content_block_stop\ndata: {"type": "content_block_stop", "index": 1}\n\n'

    stream_part2 = block1_start + block1_delta + block1_stop
    out2 = r.feed(stream_part2.encode()) + r.feed(b"")

    assert texts(out2) == ["world"]


def responses_event(payload: dict) -> str:
    return f"event: {payload['type']}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"


def responses_payloads(output: bytes) -> list[dict]:
    found = []
    for block in output.decode().split("\n\n"):
        for line in block.split("\n"):
            if line.startswith("data:"):
                found.append(json.loads(line[5:]))
    return found


TEXT_THEN_CALL = [
    {"type": "response.output_text.delta", "output_index": 0, "content_index": 0, "delta": "if a <"},
    {"type": "response.output_text.done", "output_index": 0, "content_index": 0, "text": "if a <"},
    {"type": "response.output_item.added", "output_index": 1, "item": {"type": "function_call", "name": "run"}},
    {"type": "response.function_call_arguments.delta", "output_index": 1, "delta": '{"cmd":"ls"}'},
    {"type": "response.function_call_arguments.done", "output_index": 1, "arguments": '{"cmd":"ls"}'},
]


def test_responses_api_text_ending_with_lt_does_not_move_into_the_next_item():
    r = SSERestorer(MAPPING)
    out = r.feed("".join(responses_event(e) for e in TEXT_THEN_CALL).encode()) + r.feed(b"")
    payloads = responses_payloads(out)
    assert payloads[0]["delta"] == "if a <"
    assert payloads[1]["text"] == "if a <"
    assert payloads[3]["delta"] == '{"cmd":"ls"}'


def test_responses_api_events_after_a_done_event_are_emitted_without_waiting():
    r = SSERestorer(MAPPING)
    out = r.feed("".join(responses_event(e) for e in TEXT_THEN_CALL[:3]).encode())
    assert [e["type"] for e in responses_payloads(out)] == [e["type"] for e in TEXT_THEN_CALL[:3]]


@pytest.mark.parametrize("done", [
    {"type": "response.output_item.done", "output_index": 0, "item": {"type": "message"}},
    {"type": "response.content_part.done", "output_index": 0, "content_index": 0, "part": {"type": "output_text"}},
])
def test_responses_api_item_and_part_done_release_the_hold(done):
    r = SSERestorer(MAPPING)
    delta = {"type": "response.output_text.delta", "output_index": 0, "content_index": 0, "delta": "x <"}
    out = r.feed((responses_event(delta) + responses_event(done)).encode())
    assert [e["type"] for e in responses_payloads(out)] == [delta["type"], done["type"]]
    assert responses_payloads(out)[0]["delta"] == "x <"


def test_responses_api_placeholder_split_across_deltas_of_one_item_is_restored():
    r = SSERestorer(MAPPING)
    events = [
        {"type": "response.output_text.delta", "output_index": 0, "content_index": 0, "delta": "key <<SECRET"},
        {"type": "response.output_text.delta", "output_index": 0, "content_index": 0, "delta": "_1>> end"},
        {"type": "response.output_text.done", "output_index": 0, "content_index": 0, "text": "key <<SECRET_1>> end"},
    ]
    out = r.feed("".join(responses_event(e) for e in events).encode()) + r.feed(b"")
    payloads = responses_payloads(out)
    assert payloads[0]["delta"] + payloads[1]["delta"] == f"key {KEY} end"
    assert payloads[2]["text"] == f"key {KEY} end"


def test_responses_api_done_of_another_item_keeps_the_hold():
    r = SSERestorer(MAPPING)
    events = [
        {"type": "response.output_text.delta", "output_index": 0, "content_index": 0, "delta": "key <<SECRET"},
        {"type": "response.output_item.done", "output_index": 1, "item": {"type": "reasoning"}},
        {"type": "response.output_text.delta", "output_index": 0, "content_index": 0, "delta": "_1>> end"},
    ]
    out = r.feed("".join(responses_event(e) for e in events).encode()) + r.feed(b"")
    payloads = responses_payloads(out)
    assert payloads[0]["delta"] + payloads[2]["delta"] == f"key {KEY} end"


def test_responses_api_done_of_another_content_part_keeps_the_hold():
    r = SSERestorer(MAPPING)
    events = [
        {"type": "response.output_text.delta", "output_index": 0, "content_index": 0, "delta": "key <<SECRET"},
        {"type": "response.content_part.done", "output_index": 0, "content_index": 1, "part": {"type": "output_text"}},
        {"type": "response.output_text.delta", "output_index": 0, "content_index": 0, "delta": "_1>> end"},
    ]
    out = r.feed("".join(responses_event(e) for e in events).encode()) + r.feed(b"")
    payloads = responses_payloads(out)
    assert payloads[0]["delta"] + payloads[2]["delta"] == f"key {KEY} end"


def test_responses_api_item_done_without_an_output_index_does_not_break_the_stream():
    r = SSERestorer(MAPPING)
    events = [
        {"type": "response.output_text.delta", "output_index": 0, "content_index": 0, "delta": "x <"},
        {"type": "response.output_item.done", "item": {"type": "message"}},
        {"type": "response.output_text.delta", "output_index": 0, "content_index": 0, "delta": "y"},
    ]
    out = r.feed("".join(responses_event(e) for e in events).encode()) + r.feed(b"")
    assert [e["type"] for e in responses_payloads(out)] == [e["type"] for e in events]


@pytest.mark.parametrize("event", [
    {"type": "response.created", "response": {"instructions": "answer with <"}},
    {"type": "response.completed", "response": {"output": [{"content": [{"text": "if a <"}]}]}},
])
def test_responses_api_complete_strings_outside_deltas_do_not_hold_the_stream(event):
    r = SSERestorer(MAPPING)
    after = {"type": "response.in_progress", "response": {"status": "in_progress"}}
    out = r.feed((responses_event(event) + responses_event(after)).encode())
    assert [e["type"] for e in responses_payloads(out)] == [event["type"], after["type"]]


def test_responses_api_text_and_arguments_of_the_same_item_index_do_not_share_a_hold():
    r = SSERestorer(MAPPING)
    events = [
        {"type": "response.function_call_arguments.delta", "output_index": 0, "delta": '{"a":"<'},
        {"type": "response.output_text.delta", "output_index": 0, "delta": "plain"},
        {"type": "response.function_call_arguments.delta", "output_index": 0, "delta": '"}'},
    ]
    out = r.feed("".join(responses_event(e) for e in events).encode()) + r.feed(b"")
    payloads = responses_payloads(out)
    assert payloads[1]["delta"] == "plain"
    assert payloads[0]["delta"] + payloads[2]["delta"] == '{"a":"<"}'


def test_openai_two_choices_restores_each_independently():
    r = SSERestorer(MAPPING)

    def openai_event(text: str, index: int = 0) -> str:
        payload = {"choices": [{"index": index, "delta": {"content": text}}]}
        return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"

    stream = (
        openai_event("key: <<SEC", 0) +
        openai_event("RET_1>>", 0) +
        openai_event("key2: <<SEC", 1) +
        openai_event("RET_12>>", 1) +
        "data: [DONE]\n\n"
    )

    out = r.feed(stream.encode()) + r.feed(b"")
    result_texts = texts(out)

    assert result_texts == ["key: ", KEY, "key2: ", "second-secret-value"]
    assert out.endswith(b"data: [DONE]\n\n")


PEM = ("-----BEGIN PRIVATE KEY-----\n"
       "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDtest\n"
       "-----END PRIVATE KEY-----")


def test_text_delta_starting_with_brace_escapes_by_event_type_not_first_char():
    mapping = {"<<SECRET_1>>": PEM}
    r = SSERestorer(mapping)

    stream = anthropic_event('{"example": "<<SECRET_1>>"} explained above')
    out = r.feed(stream.encode()) + r.feed(b"")

    result_texts = texts(out)
    assert len(result_texts) == 1
    result = result_texts[0]

    assert "\n" in result
    assert "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDtest" in result
    assert "BEGIN PRIVATE KEY-----\nMIIE" in result


def test_object_keys_get_same_escaping_as_values():
    mapping = {"<<SECRET_1>>": PEM}
    body = json.dumps({"<<SECRET_1>>": "value"})
    restored = restore_json(body, mapping)

    parsed = json.loads(restored)

    keys = list(parsed.keys())
    assert len(keys) == 1
    key = keys[0]
    assert "BEGIN PRIVATE KEY-----\nMIIE" in key or "BEGIN PRIVATE KEY-----\\nMIIE" in key
    assert parsed[key] == "value"


def test_json_like_value_in_arguments_gets_two_levels_of_escaping():
    mapping = {"<<SECRET_1>>": PEM}
    nested = json.dumps({"key": "<<SECRET_1>>"})
    body = json.dumps({"arguments": [nested]})

    parsed = json.loads(restore_json(body, mapping))
    inner = json.loads(parsed["arguments"][0])

    assert inner == {"key": PEM}


def test_plain_string_in_arguments_gets_one_level_of_escaping():
    mapping = {"<<SECRET_1>>": PEM}
    body = json.dumps({"arguments": ["<<SECRET_1>>"]})

    parsed = json.loads(restore_json(body, mapping))

    assert parsed["arguments"][0] == PEM


def test_regular_field_gets_one_level_of_escaping():
    mapping = {"<<SECRET_1>>": PEM}
    body = json.dumps({"text": "<<SECRET_1>>"})

    parsed = json.loads(restore_json(body, mapping))

    assert parsed["text"] == PEM


def test_restore_json_brace_starting_prose_in_plain_field_restores_real_newlines():
    mapping = {"<<SECRET_1>>": PEM}
    body = '{"content": "{\\"example\\": \\"<<SECRET_1>>\\"} explained above"}'
    restored = restore_json(body, mapping)
    parsed = json.loads(restored)
    assert parsed["content"] == '{"example": "' + PEM + '"} explained above'
    assert "\\n" not in parsed["content"]


def test_restore_json_partial_json_starting_with_brace_keeps_two_levels():
    mapping = {"<<SECRET_1>>": PEM}
    nested = json.dumps({"key": "<<SECRET_1>>"})
    body = json.dumps({"partial_json": nested})
    restored = restore_json(body, mapping)
    inner = json.loads(json.loads(restored)["partial_json"])
    assert inner == {"key": PEM}


def test_restore_json_stringified_document_under_content_parses_outer_body_only():
    mapping = {"<<SECRET_1>>": PEM}
    nested = json.dumps({"key": "<<SECRET_1>>"})
    body = json.dumps({"content": nested})
    restored = restore_json(body, mapping)
    parsed = json.loads(restored)
    assert "\nMIIE" in parsed["content"]
    with pytest.raises(json.JSONDecodeError):
        json.loads(parsed["content"])
