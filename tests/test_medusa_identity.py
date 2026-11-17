"""Medusa 固定身份查詢、憑證邊界及本地撤銷驗收。"""

import asyncio
from dataclasses import replace

import httpx
import pytest

from deception.security.medusa_identity import IdentitySessions, MedusaIdentityError, MedusaIdentityProvider
from test_postgres_conformance import isolated_test_dsn
from test_trusted_ingress import vector_request


@pytest.mark.parametrize("mode", ["success", "unauthorized", "redirect", "malformed", "oversized", "timeout"])
def test_medusa_query_binds_only_verified_identity(isolated_test_dsn, mode):
    """只查固定身份端點，核對成功撤銷與各類遠端失敗都不回傳未驗證身份。"""
    calls = []

    def identity_endpoint(request):
        """模擬 Medusa 的最小身份介面，記錄送出內容以排除訪客路由與 cookies 洩漏。"""
        calls.append(request)
        assert request.url == "https://identity.test/store/customers/me?fields=id"
        assert request.method == "GET" and request.content == b""
        assert "cookie" not in request.headers
        if mode == "timeout":
            raise httpx.ReadTimeout("injected timeout")
        if mode == "redirect":
            return httpx.Response(302, headers={"location": "https://untrusted.test/"})
        if mode == "unauthorized":
            return httpx.Response(401)
        if mode == "malformed":
            return httpx.Response(200, json={"customer": {"email": "not-an-identity"}})
        if mode == "oversized":
            return httpx.Response(200, content=b"x" * 20000)
        return httpx.Response(200, json={"customer": {"id": "cus_synthetic"}})

    async def exercise():
        """在同一 client 上驗證成功身份、共享撤銷與不同登入憑證的隔離。"""
        sessions = IdentitySessions(isolated_test_dsn)
        async with httpx.AsyncClient(transport=httpx.MockTransport(identity_endpoint),
                                     cookies={"private-other-session": "do-not-forward"}) as client:
            provider = MedusaIdentityProvider(client=client, origin="https://identity.test",
                publishable_key="pk_synthetic", identity_key=b"x" * 32, sessions=sessions,
                environment_id="test", deployment_id="test")
            request = replace(vector_request(), headers=(("authorization", "Bearer synthetic-token"),
                                                         ("x-session-id", "visitor-selected")))
            if mode != "success":
                with pytest.raises(MedusaIdentityError):
                    await provider(request)
                assert len(calls) == 1
                return
            first = await provider(request)
            assert len(first.session_id) == 64 and first.session_id != "visitor-selected"
            assert await provider(request) == first
            assert sessions.revoke_identity(first)
            assert not sessions.revoke_identity(first)
            with pytest.raises(MedusaIdentityError, match="revoked"):
                await provider(request)
            another = await provider(replace(request, headers=(("authorization", "Bearer new-token"),)))
            assert another.session_id != first.session_id

    asyncio.run(exercise())


@pytest.mark.parametrize("headers", [(), (("authorization", "Bearer one"), ("authorization", "Bearer two")),
    (("authorization", "Bearer one"), ("cookie", "connect.sid=two")),
    (("cookie", "connect.sid=one; connect.sid=two"),)])
def test_medusa_rejects_ambiguous_credentials_before_network(isolated_test_dsn, headers):
    """缺少或具有歧義的身份憑證不得觸發遠端驗證或資料庫寫入。"""

    def forbidden(request):
        """若出現未授權外連，立即使測試失敗。"""
        pytest.fail("network request must not occur")

    async def exercise():
        """以固定身份服務設定驗證各個憑證負例。"""
        async with httpx.AsyncClient(transport=httpx.MockTransport(forbidden)) as client:
            provider = MedusaIdentityProvider(client=client, origin="https://identity.test",
                publishable_key="pk_synthetic", identity_key=b"x" * 32,
                sessions=IdentitySessions(isolated_test_dsn), environment_id="test", deployment_id="test")
            with pytest.raises(MedusaIdentityError):
                await provider(replace(vector_request(), headers=headers))

    asyncio.run(exercise())
