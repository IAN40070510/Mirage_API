"""獨立 Medusa 服務的真實身份、登出與 Mirage Session 世界驗收。"""

import asyncio
from dataclasses import replace
import os
import secrets
from uuid import uuid4

import httpx
import pytest

from deception.security.medusa_identity import IdentitySessions, MedusaIdentityError, MedusaIdentityProvider
from deception.world.session import PostgresSessionWorlds
from test_postgres_conformance import isolated_test_dsn
from test_trusted_ingress import vector_request


async def create_test_customer(client, origin, email, password):
    """用隔離 Medusa 的合成管理員建立 publishable key 與一次性顧客。

    輸入為測試 HTTP client、固定服務 origin 及合成管理員帳密；回傳
    (publishable key, 顧客 Bearer)。本函式會在**測試** Medusa 寫入 API key
    與顧客，任一登入／註冊 HTTP 狀態非 200 時立即中止驗收。
    """
    login = await client.post(origin + "/auth/user/emailpass", json={"email": email, "password": password})
    assert login.status_code == 200
    admin_headers = {"authorization": "Bearer " + login.json()["token"]}
    created = await client.post(origin + "/admin/api-keys", headers=admin_headers,
                                 json={"title": "Mirage isolated identity test", "type": "publishable"})
    assert created.status_code == 200
    publishable = created.json()["api_key"]["token"]
    store_headers = {"x-publishable-api-key": publishable}
    customer_credentials = {"email": f"mirage-{uuid4().hex}@example.invalid",
                            "password": secrets.token_urlsafe(32)}
    registration = await client.post(origin + "/auth/customer/emailpass/register", json=customer_credentials)
    assert registration.status_code == 200
    store_headers["authorization"] = "Bearer " + registration.json()["token"]
    customer = await client.post(origin + "/store/customers", headers=store_headers,
                                 json={"email": customer_credentials["email"]})
    assert customer.status_code == 200
    customer_login = await client.post(origin + "/auth/customer/emailpass", json=customer_credentials)
    assert customer_login.status_code == 200
    bearer = "Bearer " + customer_login.json()["token"]
    return publishable, bearer


def test_real_medusa_customer_identity_and_logout(isolated_test_dsn):
    """在獨立 schema 中核對 Medusa Bearer／Cookie 身份及撤銷邊界。

    必須先提供隔離 Medusa origin 與合成管理員帳密；未提供時明確 skip。
    案例建立一次性顧客、世界與身份紀錄，確認 Bearer 撤銷與 Cookie
    登出後不能沿用原世界；schema 由 fixture 測後刪除。
    """
    origin = os.environ.get("MIRAGE_MEDUSA_TEST_ORIGIN")
    email = os.environ.get("MIRAGE_MEDUSA_TEST_ADMIN_EMAIL")
    password = os.environ.get("MIRAGE_MEDUSA_TEST_ADMIN_PASSWORD")
    if not all((origin, email, password)):
        pytest.skip("requires isolated Medusa test origin and synthetic administrator credentials")

    async def exercise():
        """在記憶體使用合成憑證，驗證身份解析、世界重用及雙路撤銷。

        只向指定的測試 origin 發送管理員／顧客請求，並把合成 Session
        寫入 fixture 的獨立 PostgreSQL schema；驗證失敗時由 assert 中止。
        """
        async with httpx.AsyncClient(base_url=origin, trust_env=False, timeout=15) as client:
            publishable, bearer = await create_test_customer(client, origin, email, password)
            sessions = IdentitySessions(isolated_test_dsn)
            provider = MedusaIdentityProvider(client=client, origin=origin, publishable_key=publishable,
                identity_key=secrets.token_bytes(32), sessions=sessions, environment_id="lab", deployment_id="test",
                allow_loopback_http=True)
            original = vector_request()
            verified = await provider(replace(original, headers=(("authorization", bearer),)))
            runtime = PostgresSessionWorlds(isolated_test_dsn)
            first = runtime.resolve(verified, {"owner": "synthetic-customer-world"}, now=100, ttl=60)
            again = await provider(replace(original, headers=(("authorization", bearer),)))
            assert runtime.inspect_binding(again, now=101) == first
            session_response = await client.post("/auth/session", headers={"authorization": bearer})
            assert session_response.status_code == 200
            cookie = client.cookies.get("connect.sid")
            assert cookie
            cookie_request = replace(original, headers=(("cookie", "connect.sid=" + cookie),))
            cookie_binding = await provider(cookie_request)
            assert cookie_binding.session_id != verified.session_id
            assert sessions.revoke_identity(verified)
            with pytest.raises(MedusaIdentityError):
                await provider(replace(original, headers=(("authorization", bearer),)))
            logout = await client.delete("/auth/session")
            assert logout.status_code == 200
            with pytest.raises(MedusaIdentityError):
                await provider(cookie_request)

    asyncio.run(exercise())
