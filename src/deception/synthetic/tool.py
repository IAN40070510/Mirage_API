"""E 查詢介面：只讀固定資料集，未知 ID 不會觸發新的隨機生成。"""

from deception.profile_builder import OperationContext

from .generator import SyntheticError, checked_dataset
from .models import DatasetScope, Product, SyntheticDataset, Variant


class SyntheticTool:
    """每個 instance 綁定一個已驗證 scope，並保存不對外暴露的資料複本。"""

    def __init__(self, dataset: SyntheticDataset, *, expected_scope: DatasetScope,
                 profile: OperationContext | None = None):
        checked = checked_dataset(dataset, dataset.config)
        if checked.config.scope != expected_scope:
            raise SyntheticError("Dataset scope does not match expected scope")
        if profile is not None:
            source = profile.source
            if (source.platform_id, source.platform_version, source.spec_sha256) != (
                expected_scope.platform_id, expected_scope.platform_version, expected_scope.spec_sha256
            ):
                raise SyntheticError("Dataset identity does not match D Profile context")
        # D 的核准狀態與 I 的 gate 判定不會因 E 查詢而改變。
        self._products = {product.id: product for product in checked.products}
        self._variants = {variant.id: variant for variant in checked.variants}

    def get_product(self, product_id: str) -> Product | None:
        """查詢固定商品；缺少時回 None，供 F/H 自行決定後續情境。"""
        product = self._products.get(product_id)
        return product.model_copy(deep=True) if product is not None else None

    def get_variant(self, variant_id: str) -> Variant | None:
        """查詢固定變體，回傳複本以防呼叫者修改後污染其他查詢。"""
        variant = self._variants.get(variant_id)
        return variant.model_copy(deep=True) if variant is not None else None

    def list_products(self, offset: int = 0, limit: int = 100) -> list[Product]:
        """依生成順序分頁，重複呼叫不消耗亂數或新增實體。"""
        if type(offset) is not int or type(limit) is not int or offset < 0 or not 1 <= limit <= 1000:
            raise SyntheticError("Pagination requires offset >= 0 and limit between 1 and 1000")
        return [product.model_copy(deep=True) for product in list(self._products.values())[offset:offset + limit]]

    def get_variants(self, product_id: str) -> list[Variant]:
        """依商品上的關聯順序取得變體；未知商品回空列表。"""
        product = self._products.get(product_id)
        return [self._variants[variant_id].model_copy(deep=True) for variant_id in product.variant_ids] if product else []
