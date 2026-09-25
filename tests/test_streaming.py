import json

from keyfence.streaming import Event, SSERestorer, partial_suffix, restore

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


def test_two_text_blocks_first_ends_with_lt_does_not_move_to_second():
    r = SSERestorer(MAPPING)
    
    # Block 0: content_block_start, then delta ending with "<", then content_block_stop
    block0_start = 'event: content_block_start\ndata: {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}\n\n'
    block0_delta = 'event: content_block_delta\ndata: {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "hello <"}}\n\n'
    block0_stop = 'event: content_block_stop\ndata: {"type": "content_block_stop", "index": 0}\n\n'
    
    # Block 1: another text block
    block1_start = 'event: content_block_start\ndata: {"type": "content_block_start", "index": 1, "content_block": {"type": "text", "text": ""}}\n\n'
    block1_delta = 'event: content_block_delta\ndata: {"type": "content_block_delta", "index": 1, "delta": {"type": "text_delta", "text": "world"}}\n\n'
    block1_stop = 'event: content_block_stop\ndata: {"type": "content_block_stop", "index": 1}\n\n'
    
    stream = block0_start + block0_delta + block0_stop + block1_start + block1_delta + block1_stop
    
    out = r.feed(stream.encode()) + r.feed(b"")
    
    # Extract text from both blocks
    result_texts = texts(out)
    
    # Block 0 should have "hello <" (the "<" stays in block 0)
    # Block 1 should have "world" (no "<" prepended)
    assert result_texts == ["hello <", "world"], f"Expected ['hello <', 'world'], got {result_texts}"


def test_events_after_block_stop_emitted_without_waiting_for_next_block():
    r = SSERestorer(MAPPING)
    
    block0_start = 'event: content_block_start\ndata: {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}\n\n'
    block0_delta = 'event: content_block_delta\ndata: {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "hello <"}}\n\n'
    block0_stop = 'event: content_block_stop\ndata: {"type": "content_block_stop", "index": 0}\n\n'
    
    # Feed up to and including block 0's content_block_stop
    stream_part1 = block0_start + block0_delta + block0_stop
    out1 = r.feed(stream_part1.encode())
    
    # Block 0's events should be emitted now (queue drained at content_block_stop)
    assert texts(out1) == ["hello <"]
    
    # Now feed block 1 - should work independently
    block1_start = 'event: content_block_start\ndata: {"type": "content_block_start", "index": 1, "content_block": {"type": "text", "text": ""}}\n\n'
    block1_delta = 'event: content_block_delta\ndata: {"type": "content_block_delta", "index": 1, "delta": {"type": "text_delta", "text": "world"}}\n\n'
    block1_stop = 'event: content_block_stop\ndata: {"type": "content_block_stop", "index": 1}\n\n'
    
    stream_part2 = block1_start + block1_delta + block1_stop
    out2 = r.feed(stream_part2.encode()) + r.feed(b"")
    
    assert texts(out2) == ["world"]


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
