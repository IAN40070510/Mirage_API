"""Mirage 內的 Gateway 部署組裝介面，不啟動原 Gateway 或連線資料庫。"""

import asyncio
import os
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from integrations.msdss.gateway_bootstrap import (
    GatewayIntegrationSettings, configure_from_environment, configure_gateway_state,
)


@pytest.fixture
def setup_gateway(monkeypatch):
    """提供實際 MSDSS 型別路徑與短期驗收金鑰，結束時釋放 HTTP client。"""
    root = Path(os.environ.get("MSDSS_ROOT", Path(__file__).resolve().parents[2] / "MSDSS"))
    if not (root / "src/msdss/adapters/attack_assessment.py").is_file():
        pytest.skip("requires local MSDSS adapter checkout")
    monkeypatch.syspath_prepend(str(root / "src"))
    key = Ed25519PrivateKey.generate()
    settings = GatewayIntegrationSettings(deployment=dict(issuer="gateway", audience="mirage",
        environment_id="isolated-demo", deployment_id="isolated-demo", source_id="local-demo-detector",
        service_id="synthetic-store", site_id="demo-store", public_keys={"key": key.public_key().public_bytes_raw().hex()}),
        kid="key", mirage_origin="https://mirage.test", medusa_origin="https://medusa.test")
    client = httpx.AsyncClient(trust_env=False)
    state = SimpleNamespace(client=client, decision_policy="original", upstream="https://backend.test")
    raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    yield state, settings, raw
    asyncio.run(client.aclose())


def test_bootstrap_preserves_observe_policy_and_owned_clients(setup_gateway):
    """安裝 dispatcher 不自動核准 enforcement，且保留原 client 與真實上游。"""
    state, settings, raw = setup_gateway
    client = state.client
    configure_gateway_state(state, settings=settings, postgres_dsn="postgresql://test@localhost/mirage",
                            signing_key=raw, identity_key=b"x" * 32, publishable_key="synthetic-publishable")
    assert not state.decision_policy.enforcement_enabled and not state.decision_policy.deception_approved
    assert str(state.deception_dispatcher.origin) == "https://mirage.test"
    assert state.client is client and state.upstream == "https://backend.test"


@pytest.mark.parametrize("failure", ["key", "identity_http", "existing", "client"])
def test_bootstrap_rejects_invalid_settings_before_state_update(setup_gateway, failure):
    """金鑰不符、身份 HTTP、重複 dispatcher 或無 client 時不留下半套政策。"""
    state, settings, raw = setup_gateway
    if failure == "key":
        raw = Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    elif failure == "identity_http":
        settings = settings.model_copy(update={"medusa_origin": "http://medusa.test"})
    elif failure == "existing":
        state.deception_dispatcher = "original-dispatcher"
    else:
        del state.client
    with pytest.raises(ValueError):
        configure_gateway_state(state, settings=settings, postgres_dsn="postgresql://test@localhost/mirage",
                                signing_key=raw, identity_key=b"x" * 32, publishable_key="synthetic-publishable")
    assert state.decision_policy == "original"
    assert getattr(state, "deception_dispatcher", None) == ("original-dispatcher" if failure == "existing" else None)


def test_bootstrap_reads_separate_secret_files(setup_gateway, tmp_path, monkeypatch):
    """部署入口讀取分開的秘密檔，只有明確 true 的政策開關才啟用。"""
    state, settings, raw = setup_gateway
    settings = settings.model_copy(update={"enforcement_enabled": True, "deception_approved": True})
    files = {
        "MIRAGE_GATEWAY_SETTINGS_FILE": settings.model_dump_json().encode(),
        "MIRAGE_GATEWAY_SIGNING_KEY_FILE": raw,
        "MIRAGE_IDENTITY_KEY_FILE": b"x" * 32,
        "MIRAGE_MEDUSA_PUBLISHABLE_KEY_FILE": b"synthetic-publishable\n",
    }
    for name, data in files.items():
        path = tmp_path / name
        path.write_bytes(data)
        monkeypatch.setenv(name, str(path))
    monkeypatch.setenv("MIRAGE_POSTGRES_DSN", "postgresql://test@localhost/mirage")
    configure_from_environment(state)
    assert state.decision_policy.enforcement_enabled and state.decision_policy.deception_approved


@pytest.mark.parametrize("enabled", [False, True])
def test_actual_gateway_optional_import_boundary(setup_gateway, monkeypatch, enabled):
    """其他模組不可用時，未啟用者可正常啟動，明確啟用者停止而不默默改走上游。"""
    import builtins
    import importlib

    root = Path(os.environ.get("MSDSS_ROOT", Path(__file__).resolve().parents[2] / "MSDSS"))
    monkeypatch.syspath_prepend(str(root))
    gateway = importlib.import_module("sentinel.gateway.app")
    monkeypatch.setenv("GATEWAY_MODEL_DIR", "")
    # This test is specifically about an absent optional integration, not
    # transport configuration. Do not inherit a certificate from the host.
    for name in (
        "GATEWAY_MIRAGE_MTLS_CA_FILE",
        "GATEWAY_MIRAGE_MTLS_CERT_FILE",
        "GATEWAY_MIRAGE_MTLS_KEY_FILE",
    ):
        monkeypatch.delenv(name, raising=False)
    if enabled:
        monkeypatch.setenv("MIRAGE_GATEWAY_SETTINGS_FILE", "synthetic-missing-settings.json")
    else:
        monkeypatch.delenv("MIRAGE_GATEWAY_SETTINGS_FILE", raising=False)
    original_import = builtins.__import__
    attempted = []

    def unavailable_integration(name, globals=None, locals=None, fromlist=(), level=0):
        """模擬 Gateway 尚未安裝 Mirage 組裝器，核對 guarded import 的真正執行邊界。"""
        if name == "integrations.msdss.gateway_bootstrap":
            attempted.append(name)
            raise ModuleNotFoundError("synthetic unavailable Mirage integration")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", unavailable_integration)

    async def exercise():
        """使用已修改 Gateway 的真實 lifespan，核對原 client 在結束後確實關閉。"""
        if enabled:
            with pytest.raises(ModuleNotFoundError, match="synthetic unavailable"):
                async with gateway.lifespan(gateway.app):
                    pytest.fail("enabled unavailable integration must stop startup")
        else:
            async with gateway.lifespan(gateway.app):
                assert not gateway.app.state.client.is_closed
                assert not gateway.app.state.decision_policy.enforcement_enabled
        assert gateway.app.state.client.is_closed

    asyncio.run(exercise())
    assert bool(attempted) is enabled



def test_actual_gateway_requires_dedicated_mtls_for_configured_mirage(
    setup_gateway, monkeypatch,
):
    """可信 Mirage 已安裝也不能用普通 Medusa HTTP client 啟動遠端 DECEIVE。"""
    import importlib

    root = Path(os.environ.get("MSDSS_ROOT", Path(__file__).resolve().parents[2] / "MSDSS"))
    monkeypatch.syspath_prepend(str(root))
    gateway = importlib.import_module("sentinel.gateway.app")
    monkeypatch.setenv("GATEWAY_MODEL_DIR", "")
    monkeypatch.setenv("MIRAGE_GATEWAY_SETTINGS_FILE", "synthetic-missing-settings.json")
    for name in (
        "GATEWAY_MIRAGE_MTLS_CA_FILE",
        "GATEWAY_MIRAGE_MTLS_CERT_FILE",
        "GATEWAY_MIRAGE_MTLS_KEY_FILE",
    ):
        monkeypatch.delenv(name, raising=False)

    async def exercise():
        """驗證阻止啟動並關閉共用 Medusa client，不觸發 Mirage 的業務請求。"""
        with pytest.raises(ValueError, match="dedicated mTLS"):
            async with gateway.lifespan(gateway.app):
                pytest.fail("trusted Mirage without mTLS must never start")
        assert gateway.app.state.deception_client is None
        assert gateway.app.state.client.is_closed

    asyncio.run(exercise())
