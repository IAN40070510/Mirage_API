"""N/M 整合驗證：從真正 FastAPI 請求取得備援，回送最後一次 I 驗證的相同 bytes。"""

import json

from fastapi.testclient import TestClient

from deception.api.pipeline import create_app

from test_generation import function_backend, generation_stack, make_pipeline
from test_recovery import enable_recovery
from test_scenarios import NOW, assessment_for


def test_http_fallback_is_exactly_the_final_gate_candidate(generation_stack):
    """生成失敗後 N 的同商品備援經 M 加標頭再驗 I，HTTP 封套與最後 gate 完全一致。"""
    backend, calls = function_backend(value=1)
    pipeline, _, _ = make_pipeline(generation_stack, backend=backend)
    enable_recovery(pipeline, values={"description": "這是管理者核准的合成商品備援說明。"})
    gate = pipeline.gate
    checked = []

    class RecordingGate:
        def validate(self, request):
            """記錄內部備援與最終 HTTP 封套，仍使用真正 I 驗證合成契約。"""
            checked.append(request.model_copy(deep=True))
            return gate.validate(request)

    pipeline.gate = RecordingGate()

    def verified_assessment(request):
        """模擬已完成來源認證的伺服器接收層，判定綁定本次 A 請求指紋。"""
        return assessment_for(request)

    app = create_app(orchestrator=pipeline, runtime=generation_stack["runtime"],
                     generation_config=generation_stack["config"], dataset=generation_stack["dataset"],
                     assessment_provider=verified_assessment, now=NOW)
    original = generation_stack["dataset"].model_dump_json()
    request = generation_stack["request"]
    with TestClient(app, base_url="https://shop.test") as client:
        response = client.get(request.raw_url, headers={"X-Request-ID": "http-nm-fallback"})
    assert response.status_code == 200, response.text
    final = checked[-1]
    assert len(checked) == 2, "備援經 I 一次，最終 M 封套再經 I 一次"
    assert response.status_code == final.status_code
    assert response.content == final.body.encode("utf-8")
    assert dict(response.headers) == {key.lower(): value for key, value in final.headers.items()}
    assert int(response.headers["content-length"]) == len(response.content)
    assert response.headers["x-request-id"] == "http-nm-fallback"
    assert json.loads(response.content)["product"]["description"] == "這是管理者核准的合成商品備援說明。"
    assert generation_stack["dataset"].model_dump_json() == original
    assert len(calls["generator"]) == 2
