"""從本機已安裝清單選模型並固定 digest；不下載、不接受任意遠端 endpoint。"""

import asyncio
import json
import re
from urllib.parse import urlsplit, urlunsplit

import httpx2
from pydantic import Field

from deception.synthetic.models import SyntheticModel

from .models import LLMConfig

MAX_MODEL_METADATA_BYTES = 1024 * 1024
MODEL_METADATA_TIMEOUT_SECONDS = 15


class InstalledModel(SyntheticModel):
    """只公開本機模型的完整名稱與內容摘要，不把 cloud 別名列為可選項。"""

    name: str = Field(min_length=1, max_length=256)
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")


def _digest(value) -> str:
    """接受服務常見的 sha256 前綴，仍要求完整的 64 位小寫十六進位摘要。"""
    if not isinstance(value, str):
        raise ValueError("Model digest must be a complete SHA-256 string")
    value = value.removeprefix("sha256:")
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("Model digest must contain 64 lowercase hexadecimal characters")
    return value


def _local_config(config: LLMConfig) -> LLMConfig:
    """重驗可能被修改的設定，沿用本機 URL／模型名稱限制並拒絕測試模式。"""
    checked = LLMConfig.model_validate(config.model_dump(mode="json"))
    if checked.execution_mode != "local":
        raise ValueError("Installed-model selection requires local execution")
    return checked


def parse_local_models(metadata: dict, config: LLMConfig) -> tuple[InstalledModel, ...]:
    """核對清單結構、名稱與 digest，過濾 cloud／remote 並拒絕歧義名稱。"""
    config = _local_config(config)
    if not isinstance(metadata, dict) or not isinstance(metadata.get("models"), list):
        raise ValueError("Ollama model metadata requires a models array")
    found = {}
    for item in metadata["models"]:
        if not isinstance(item, dict):
            raise ValueError("Ollama model entries must be objects")
        details = item.get("details", {})
        if not isinstance(details, dict):
            raise ValueError("Ollama model details must be an object")
        names = {item[key] for key in ("name", "model") if key in item and isinstance(item[key], str)}
        if any("cloud" in name.lower() for name in names) or any(
                data.get(key) not in (None, "") for data in (item, details) for key in ("remote_model", "remote_host")):
            continue
        if not names or len(names) != 1 or any(key in item and not isinstance(item[key], str) for key in ("name", "model")):
            raise ValueError("Ollama model name is missing or ambiguous")
        name = next(iter(names))
        digest = _digest(item.get("digest"))
        # 模型名稱與 URL 使用同一套設定驗證，不因選擇來源是 metadata 而放寬。
        LLMConfig.model_validate(dict(config.model_dump(mode="json"), model_name=name, model_digest=digest))
        if name in found:
            raise ValueError("Ollama model names must be unique")
        found[name] = InstalledModel(name=name, digest=digest)
    return tuple(found[name] for name in sorted(found))


async def list_local_models(config: LLMConfig, *,
                            transport: httpx2.AsyncBaseTransport | None = None) -> tuple[InstalledModel, ...]:
    """以有期限及大小上限的 GET 讀本機 /api/tags，測試可注入 transport。"""
    config = _local_config(config)
    base = urlsplit(config.base_url)
    url = urlunsplit((base.scheme, base.netloc, "/api/tags", "", ""))
    body = bytearray()
    async with asyncio.timeout(MODEL_METADATA_TIMEOUT_SECONDS):
        async with httpx2.AsyncClient(trust_env=False, follow_redirects=False,
                                      timeout=MODEL_METADATA_TIMEOUT_SECONDS, transport=transport) as client:
            async with client.stream("GET", url) as response:
                response.raise_for_status()
                async for chunk in response.aiter_bytes():
                    if len(body) + len(chunk) > MAX_MODEL_METADATA_BYTES:
                        raise ValueError("Ollama model metadata exceeds its size limit")
                    body.extend(chunk)
    return parse_local_models(json.loads(body), config)


async def select_local_model(config: LLMConfig, model_name: str | None = None, *,
                             expected_digest: str | None = None,
                             transport: httpx2.AsyncBaseTransport | None = None) -> LLMConfig:
    """選已安裝的唯一模型；省略名稱保留原 pinned digest，明確選模則固定清單摘要。"""
    checked = _local_config(config)
    name = checked.model_name if model_name is None else model_name
    # 在進行 metadata GET 之前拒絕無效／cloud 名稱，這裡永遠不發出 pull 請求。
    LLMConfig.model_validate(dict(checked.model_dump(mode="json"), model_name=name))
    required_digest = None if expected_digest is None else _digest(expected_digest)
    matches = [model for model in await list_local_models(checked, transport=transport) if model.name == name]
    if len(matches) != 1:
        raise ValueError("The selected local model is not uniquely installed")
    selected = matches[0]
    if model_name is None and selected.digest != checked.model_digest:
        raise ValueError("The configured default model digest changed")
    if required_digest is not None and selected.digest != required_digest:
        raise ValueError("The selected local model does not match the required digest")
    return LLMConfig.model_validate(dict(checked.model_dump(mode="json"),
                                       model_name=selected.name, model_digest=selected.digest))
