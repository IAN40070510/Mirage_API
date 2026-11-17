"""Renderer 的一次性准入、精確封套與 ASGI 傳輸故障驗收。"""

import asyncio
from dataclasses import replace
from unittest.mock import patch

import pytest

from deception.core.renderer import RenderingError, ResponseRenderer
from deception.world import AdmissionControl, AdmissionState, CandidateStore, ProjectionRegistry
from deception.world.transmission import AdmissionTransmission, TransmissionError, response_envelope, response_hashes
from test_candidate_handoff import candidate_and_gate
from test_renderer import render_request, pipeline_result, emit_response
from test_world_runtime import projection_evidence, scope, source


def admitted_renderer(gate, control, candidates, registry, clock):
    """建立以最終封套保存 Candidate 並核發 Registry 准入的測試整合端。"""
    evidence = projection_evidence()
    registry.register(evidence, registry_revision=1)
    handles = []

    def grant_final(candidate, request):
        """以同一 request、來源與最終 bytes 核發一張不可替換的傳輸准入。"""
        from deception.api.fingerprint import fingerprint_request

        candidate_hash, body_hash, headers_hash = response_hashes(
            candidate.status_code, candidate.headers, candidate.body_bytes)
        ref = "candidate-final"
        candidates.put(scope(), ref, response_envelope(candidate.status_code, candidate.headers,
                                                       candidate.body_bytes), expires_at=200)
        admission = control.grant(
            world_generation_id=scope().world_generation_id, request_binding_digest=fingerprint_request(request),
            candidate_ref=ref, candidate_hash=candidate_hash, immutable_body_hash=body_hash,
            semantic_headers_hash=headers_hash, projection_contract_hash=evidence.projection_contract_hash,
            authorization_revision="test", authorization_deadline=100, transmission_deadline=200,
            source=source(), projection_evidence=evidence, projection_registry=registry)
        assert admission is not None
        handle = AdmissionTransmission(control, candidates, scope(), admission, clock=clock)
        handles.append(handle)
        return handle

    return ResponseRenderer(gate, transmission_factory=grant_final), handles


def response_fixture(candidate_and_gate, *, control=None, candidates=None, registry=None):
    """以真實 OpenAPI gate 建立待傳輸回應，提供可變時鐘做邊界測試。"""
    candidate, gate = candidate_and_gate
    control = AdmissionControl() if control is None else control
    now = [1]

    def clock():
        """讀取測試控制的 Unix 時間，避開長時間 sleep。"""
        return now[0]

    renderer, handles = admitted_renderer(gate, control, candidates or CandidateStore(),
                                           registry or ProjectionRegistry(), clock)
    request = render_request()
    response = renderer.render(pipeline_result(candidate, gate, request), request)
    return response, request, control, handles[0], now


def test_admitted_renderer_sends_exact_bytes_once(candidate_and_gate):
    """正常完成保存 SEND_COMPLETED，第二次呼叫無法重用准入。"""
    response, request, control, handle, _ = response_fixture(candidate_and_gate)
    messages = emit_response(response, request)
    assert messages[1]["body"] == response.body
    assert control.state(handle.admission.admission_id) is AdmissionState.SEND_COMPLETED
    assert [event["event_name"] for event in control.transmission_events(handle.admission.admission_id)] == [
        "send_started", "response_send_attempted", "asgi_send_completed"]
    assert all(event["final_response_hash"] == handle.admission.candidate_hash
               for event in control.transmission_events(handle.admission.admission_id))
    with pytest.raises((TransmissionError, RenderingError)):
        emit_response(response, request)


def test_transmission_revalidates_unchecked_admission_before_claim(candidate_and_gate):
    """model_copy 的未驗證版本不能進入 Claim，即使呼叫端已持有准入物件。"""
    _, request, control, handle, _ = response_fixture(candidate_and_gate)
    unchecked = handle.admission.model_copy(update={"hash_encoding_version": 2})
    tampered = replace(handle, admission=unchecked)
    with pytest.raises(ValueError):
        tampered.prepare(candidate_and_gate[0], request)
    assert control.state(handle.admission.admission_id) is AdmissionState.GRANTED


@pytest.mark.parametrize("failure", ["start", "body", "cancel", "deadline", "timeout"])
def test_asgi_fault_never_reopens_admission(candidate_and_gate, failure):
    """送出開始後的錯誤、取消與期限超過均保存部分失敗，授權不能重送。"""
    response, request, control, handle, now = response_fixture(candidate_and_gate)
    scope_value = {"type": "http", "method": request.method, "scheme": "https", "path": request.path,
                   "raw_path": request.raw_path, "query_string": request.query_string,
                   "headers": [(name.encode(), value.encode()) for name, value in request.headers],
                   "server": ("shop.test", 443)}
    calls = []

    async def receive():
        """提供無 body 的已完成請求。"""
        return {"type": "http.request", "body": b""}

    async def send(message):
        """在指定 ASGI 邊界注入傳輸錯誤、取消或時鐘前進。"""
        calls.append(message["type"])
        if failure == "start" or (failure == "body" and len(calls) == 2):
            raise OSError("injected transport interruption")
        if failure == "cancel":
            raise asyncio.CancelledError()
        if failure == "deadline":
            now[0] = 200
        if failure == "timeout":
            await asyncio.sleep(60)

    expected = (asyncio.CancelledError if failure == "cancel" else
                TransmissionError if failure == "deadline" else
                TimeoutError if failure == "timeout" else OSError)
    if failure == "timeout":
        response._release_deadline_monotonic = __import__("time").monotonic() + 0.05
    with pytest.raises(expected):
        asyncio.run(response(scope_value, receive, send))
    assert control.state(handle.admission.admission_id) is AdmissionState.SEND_PARTIAL_FAILURE
    assert len(calls) == (2 if failure == "body" else 1)
    with pytest.raises((TransmissionError, RenderingError)):
        emit_response(response, request)


def test_candidate_hash_tampering_stops_before_claim(candidate_and_gate):
    """替換授權封套時，持久化比對會在 Claim 及 HTTP start 前拒絕。"""
    response, request, control, handle, _ = response_fixture(candidate_and_gate)
    forged = replace(handle, admission=handle.admission.model_copy(update={"candidate_hash": "f" * 64}))
    response._transmission = forged
    with pytest.raises(TransmissionError, match="binding_mismatch"):
        emit_response(response, request)
    assert control.state(handle.admission.admission_id) is AdmissionState.GRANTED


def test_terminal_storage_failure_keeps_unknown_send_closed(candidate_and_gate):
    """ASGI 已完成但終態寫入失聯時保留 SEND_STARTED，拒絕再次發送。"""
    response, request, control, handle, _ = response_fixture(candidate_and_gate)
    with patch.object(control, "finish_send", side_effect=ConnectionError("injected unknown outcome")):
        with pytest.raises(ConnectionError):
            emit_response(response, request)
    assert control.state(handle.admission.admission_id) is AdmissionState.SEND_STARTED
    assert handle.admission.candidate_ref in control.active_candidate_refs(now=2)
    with pytest.raises((TransmissionError, RenderingError)):
        emit_response(response, request)
