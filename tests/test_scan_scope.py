import json

import pytest
from mitmproxy import http
from mitmproxy.test import tflow, tutils
from mitmproxy.websocket import Opcode, WebSocketData, WebSocketMessage

from keyfence.addon import MAPPING_KEY, KeyFence

KEY = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"


@pytest.fixture
def guard(write_config):
    def _make(mode="redact"):
        write_config(f"mode: {mode}\n")
        kf = KeyFence()
        kf.load(None)
        return kf
    return _make


def make_flow(body, host="api.openai.com"):
    return tflow.tflow(req=tutils.treq(host=host, method=b"POST", path=b"/v1/chat/completions",
                                       content=json.dumps(body).encode()))


def make_ws_flow(host="api.openai.com"):
    flow = tflow.tflow(req=tutils.treq(host=host, method=b"GET", path=b"/v1/realtime", content=b""))
    flow.websocket = WebSocketData()
    return flow


def send_frame(kf, flow, content, from_client=True):
    message = WebSocketMessage(Opcode.TEXT, from_client, content.encode())
    flow.websocket.messages.append(message)
    kf.websocket_message(flow)
    return message


def test_a_secret_in_a_response_body_reaches_the_client(guard):
    kf = guard("placeholder")
    flow = make_flow({"content": f"my token is {KEY}"})
    kf.request(flow)
    token = next(iter(flow.metadata[MAPPING_KEY]))
    assert json.loads(flow.request.get_text())["content"] == f"my token is {token}"
    body = f'{{"content":"restored","leaked":"{KEY}"}}'.encode()
    flow.response = tutils.tresp(headers=http.Headers(content_type=b"application/json"), content=body)
    kf.responseheaders(flow)
    kf.response(flow)
    assert flow.response.get_text() == f'{{"content":"restored","leaked":"{KEY}"}}'
    assert kf.stats["scanned"] == 1 and kf.stats["findings"] == 1


def test_a_response_is_left_alone_in_redact_mode(guard):
    kf = guard("redact")
    flow = make_flow({"content": f"my token is {KEY}"})
    kf.request(flow)
    body = f'{{"leaked":"{KEY}"}}'.encode()
    flow.response = tutils.tresp(headers=http.Headers(content_type=b"application/json"), content=body)
    kf.responseheaders(flow)
    kf.response(flow)
    assert flow.response.get_text() == f'{{"leaked":"{KEY}"}}'
    assert kf.stats["scanned"] == 1 and kf.stats["findings"] == 1


def test_a_literal_marker_in_a_request_body_reaches_the_provider(guard):
    kf = guard("redact")
    for marker in ("[REDACTED:github-token]", "<<SECRET_0123456789>>"):
        flow = make_flow({"content": marker})
        kf.request(flow)
        assert flow.response is None
        assert json.loads(flow.request.get_text())["content"] == marker
    assert kf.stats["scanned"] == 2 and kf.stats["findings"] == 0


def test_only_client_websocket_frames_are_scanned(guard):
    kf = guard("redact")
    flow = make_ws_flow()
    back = send_frame(kf, flow, f"the key is {KEY}", from_client=False)
    assert back.text == f"the key is {KEY}" and not back.dropped
    assert kf.stats["scanned"] == 0
    sent = send_frame(kf, flow, f"the key is {KEY}")
    assert sent.text == "the key is [REDACTED:github-token]"
    assert kf.stats["scanned"] == 1 and kf.stats["findings"] == 1
