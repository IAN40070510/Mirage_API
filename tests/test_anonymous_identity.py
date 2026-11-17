"""來源 IP／UA 短期分組的唯讀邊界、限制與隱私驗收。"""

import asyncio

import pytest
from starlette.requests import Request

from deception.domains.ecommerce.inventory import SyntheticInventory
from deception.security.anonymous_identity import AnonymousGroups, AnonymousIdentityProvider
from deception.security.medusa_identity import MedusaIdentityError
from deception.world import WorldStoreError
from test_postgres_conformance import isolated_test_dsn
from uuid import uuid4


def request(peer="192.0.2.1", user_agent="scanner-test", forwarded="198.51.100.1"):
    """建立由 Gateway 觀察來源的合成 HTTP scope，另附不可信轉送標頭。"""
    return Request({"type": "http", "method": "GET", "path": "/products", "query_string": b"",
                    "client": (peer, 12345), "headers": [(b"user-agent", user_agent.encode()),
                    (b"x-forwarded-for", forwarded.encode()), (b"x-session-id", b"visitor-choice")]})


def test_grouping_is_short_lived_and_not_writable(isolated_test_dsn):
    """同來源與 UA 可共用只讀分組，換訊號或窗口換組，不能用它操作庫存。"""
    async def exercise():
        """驗證 NAT 合併風險、偽造來源不影響分組以及短期切換。"""
        now = [300]

        def clock():
            """提供固定窗口時鐘以驗證切換邊界。"""
            return now[0]

        provider = AnonymousIdentityProvider(key=b"a" * 32, groups=AnonymousGroups(isolated_test_dsn),
            environment_id="lab", deployment_id="test", window_seconds=60, clock=clock)
        first = await provider(request())
        assert first.access_mode == "read_only"
        assert await provider(request(forwarded="203.0.113.1")) == first
        assert (await provider(request(peer="192.0.2.2"))).session_id != first.session_id
        assert (await provider(request(user_agent="another-scanner"))).session_id != first.session_id
        runtime = SyntheticInventory(isolated_test_dsn)
        runtime.resolve(first, {"inventory": {"sku": 2}}, now=300, ttl=600)
        with pytest.raises(WorldStoreError, match="write_not_authorized"):
            runtime.reserve(first, sku="sku", quantity=1, expected_version=1, idempotency_key="attempt",
                            commit_attempt_id=uuid4(), now=301)
        now[0] = 360
        assert (await provider(request())).session_id != first.session_id

    asyncio.run(exercise())


def test_group_quota_is_shared_across_instances(isolated_test_dsn):
    """共享限額只計新分組，達限仍接受既有分組，下一個窗口可繼續。"""
    async def exercise():
        """由兩個 provider 驗證同一部署窗口的限額。"""
        providers = [AnonymousIdentityProvider(key=b"a" * 32, groups=AnonymousGroups(isolated_test_dsn),
            environment_id="lab", deployment_id="test", group_limit=1, clock=lambda: 300) for _ in range(2)]
        # 固定時鐘只用來把兩個 Instance 放到同一個限速窗口。
        first = await providers[0](request())
        assert await providers[1](request()) == first
        with pytest.raises(MedusaIdentityError, match="group_limit"):
            await providers[1](request(peer="192.0.2.2"))

    asyncio.run(exercise())
