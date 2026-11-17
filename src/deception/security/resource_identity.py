"""把已核發的匿名合成 cart.id／order.id 對回可信世界，維持原生資源流程。"""

import re
import time

from deception.domains.ecommerce.carts import SyntheticCarts


class ResourceIdentityProvider:
    """已知合成資源 ID 是該資源的存取能力，未知 ID 不推測也不回退真實服務。"""

    def __init__(self, *, fallback, resources: SyntheticCarts, environment_id: str,
                 deployment_id: str, prefix: str = "/synthetic", clock=None):
        """配置固定 API 前綴與部署，fallback 處理尚未持有資源 ID 的身份。"""
        if not prefix.startswith("/") or prefix.endswith("/"):
            raise ValueError("invalid fixed synthetic resource prefix")
        self._fallback, self._resources = fallback, resources
        self._environment_id, self._deployment_id, self._prefix = environment_id, deployment_id, prefix
        self._clock = clock or time.time

    async def __call__(self, request):
        """解析核准路徑上的合成 ID；若有顧客憑證也先確認它沒有失效。"""
        match = re.match(re.escape(self._prefix) + r"/(?:carts|orders)/((?:cart|order)_[0-9a-f]{32})(?:/|$)",
                         request.url.path)
        if match is None:
            return await self._fallback(request)
        if request.headers.getlist("authorization") or any(
            part.strip().startswith("connect.sid=") for value in request.headers.getlist("cookie")
            for part in value.split(";")):
            await self._fallback(request)
        return self._resources.resource_binding(match[1], environment_id=self._environment_id,
            deployment_id=self._deployment_id, now=int(self._clock()))
