"""本機模型選擇：固定 digest、過濾遠端別名，metadata 測試不下載模型。"""

import asyncio
from pathlib import Path

import httpx2
import pytest

from deception.llm import LLMConfig
from deception.llm.selection import list_local_models, parse_local_models, select_local_model
from deception.profile_builder.builder import read_yaml


def config(**changes):
    """獨立測試設定不依賴工作機是否安裝 Foundation 或啟動 Ollama。"""
    return LLMConfig(**dict({"model_name": "foundation-test:latest", "model_digest": "0" * 64,
                             "planner_mode": "structured_actions"}, **changes))


def test_repository_default_is_the_installed_foundation_reasoning_variant():
    """預設名稱明確指向 Reasoning 量化變體，不把它誤寫成未安裝的基礎模型。"""
    path = Path(__file__).resolve().parents[1] / "configs" / "llm.yaml"
    default = LLMConfig.model_validate(read_yaml(path.read_bytes()))
    assert default.execution_mode == "local"
    assert default.model_name == "hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF:Q4_K_M"
    assert default.planner_mode == "structured_actions"
    assert len(default.model_digest) == 64 and default.model_digest != "0" * 64
    assert default.max_output_tokens >= 1024


def transport_for(models, calls):
    """只允許 GET /api/tags；若實作新增 pull 或推論請求就使測試失敗。"""
    async def handle(request):
        """只模擬本機模型清單的 GET 回應，並記錄意外請求以阻止下載或推論。"""
        calls.append((request.method, request.url.host, request.url.path))
        assert request.method == "GET" and request.url.path == "/api/tags"
        assert request.url.host == "127.0.0.1"
        return httpx2.Response(200, json={"models": models})
    return httpx2.MockTransport(handle)


def test_list_filters_cloud_and_remote_models_without_downloading():
    """模型名稱及 metadata 任一處標示 cloud／remote 都不能成為本機選項。"""
    calls = []
    models = [
        {"name": "local-b:latest", "digest": "1" * 64},
        {"name": "gpt-oss:120b-cloud", "digest": "2" * 64},
        {"name": "remote-model:latest", "digest": "3" * 64, "remote_host": "https://example.invalid"},
        {"name": "remote-detail:latest", "digest": "4" * 64, "details": {"remote_model": "cloud-alias"}},
        {"name": "local-a:latest", "model": "local-a:latest", "digest": "sha256:" + "5" * 64},
    ]
    selected = asyncio.run(list_local_models(config(), transport=transport_for(models, calls)))
    assert [(model.name, model.digest) for model in selected] == [
        ("local-a:latest", "5" * 64), ("local-b:latest", "1" * 64)]
    assert calls == [("GET", "127.0.0.1", "/api/tags")]


def test_explicit_selection_pins_installed_digest_and_preserves_planner_mode():
    """選不同模型只替換名稱及已讀到的完整 digest，不偷偷切回原生工具模式。"""
    original = config()
    calls = []
    chosen = asyncio.run(select_local_model(original, "another-model:7b", expected_digest="1" * 64,
        transport=transport_for([{"name": "another-model:7b", "digest": "1" * 64}], calls)))
    assert chosen.model_name == "another-model:7b" and chosen.model_digest == "1" * 64
    assert chosen.planner_mode == "structured_actions"
    assert original.model_name == "foundation-test:latest" and original.model_digest == "0" * 64
    assert calls == [("GET", "127.0.0.1", "/api/tags")]


def test_default_selection_keeps_the_configured_pinned_digest():
    """省略 --model 時核對預設模型，不因 tag 更新自動接受另一份權重。"""
    original = config()
    chosen = asyncio.run(select_local_model(original, transport=transport_for(
        [{"name": original.model_name, "digest": original.model_digest}], [])))
    assert chosen == original
    with pytest.raises(ValueError, match="default model digest"):
        asyncio.run(select_local_model(original, transport=transport_for(
            [{"name": original.model_name, "digest": "1" * 64}], [])))


@pytest.mark.parametrize("models", [[], [{"name": "another:latest", "digest": "0" * 64}],
    [{"name": "foundation-test:latest", "digest": "0" * 64}] * 2])
def test_uninstalled_or_ambiguous_selection_is_rejected(models):
    """不存在或重複名稱不會下載、猜測別名或選第一筆。"""
    with pytest.raises(ValueError):
        asyncio.run(select_local_model(config(), transport=transport_for(models, [])))


def test_additional_digest_requirement_must_match_the_installed_model():
    """CLI 額外要求的 digest 不符時，不能以 metadata 直接覆寫該要求。"""
    with pytest.raises(ValueError, match="required digest"):
        asyncio.run(select_local_model(config(), "chosen:latest", expected_digest="2" * 64,
            transport=transport_for([{"name": "chosen:latest", "digest": "1" * 64}], [])))


def test_cloud_name_is_rejected_before_any_metadata_or_pull_request():
    """即使服務上有 cloud 別名，選擇該名稱也不會觸發服務請求。"""
    calls = []
    with pytest.raises(ValueError):
        asyncio.run(select_local_model(config(), "qwen3:cloud", transport=transport_for([], calls)))
    assert calls == []


def test_remote_endpoint_cannot_be_introduced_by_mutating_configuration():
    """選模入口重新驗證可變設定，不接受 model_copy 繞過 loopback 限制。"""
    altered = config().model_copy(update={"base_url": "https://example.invalid/v1"})
    calls = []
    with pytest.raises(ValueError):
        asyncio.run(list_local_models(altered, transport=transport_for([], calls)))
    assert calls == []


@pytest.mark.parametrize("metadata", [{}, {"models": {}}, {"models": [None]},
    {"models": [{"name": "local:latest", "digest": "short"}]},
    {"models": [{"name": "local:latest", "model": "different:latest", "digest": "0" * 64}]}])
def test_malformed_metadata_does_not_produce_selectable_models(metadata):
    """不完整 digest、非標準結構或相互矛盾的名稱都明確拒絕。"""
    with pytest.raises(ValueError):
        parse_local_models(metadata, config())


def test_model_metadata_size_limit_is_enforced():
    """即使是 loopback 回應，過大的 metadata 也不能無限載入記憶體。"""
    async def handle(request):
        """回傳超過一 MiB 的本機 metadata，觸發讀取大小上限。"""
        return httpx2.Response(200, content=b"x" * (1024 * 1024 + 1))
    with pytest.raises(ValueError, match="size limit"):
        asyncio.run(list_local_models(config(), transport=httpx2.MockTransport(handle)))


def test_model_listing_does_not_follow_redirects():
    """本機 metadata 不能透過 HTTP redirect 將列模請求轉到外部服務。"""
    calls = []
    async def handle(request):
        """回傳指向外部站點的 redirect，確認模型清單讀取不會跟隨。"""
        calls.append(str(request.url))
        return httpx2.Response(302, headers={"Location": "https://example.invalid/models"})
    with pytest.raises(httpx2.HTTPStatusError):
        asyncio.run(list_local_models(config(), transport=httpx2.MockTransport(handle)))
    assert len(calls) == 1 and calls[0] == "http://127.0.0.1:11434/api/tags"
