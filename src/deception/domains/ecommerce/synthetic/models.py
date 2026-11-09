"""電商商品、變體、價格與可重建資料集模型。"""

from typing import Literal

from pydantic import Field, field_validator, model_validator

from deception.common.models import DatasetScope, SLUG, SyntheticModel
from deception.common.data import CompositionData


class SyntheticConfig(SyntheticModel):
    """商品資料規則；金額為指定幣別的最小單位整數，不做匯率換算。"""

    schema_version: Literal[1] = 1
    scope: DatasetScope
    seed: int = Field(ge=0, le=2**63 - 1)
    product_count: int = Field(default=10, ge=0, le=1000)
    variants_per_product: int = Field(default=2, ge=1, le=20)
    locale: Literal["en_US", "zh_TW"] = "en_US"
    currency_code: Literal["usd", "eur", "twd"] = "usd"
    price_min_minor: int = Field(default=100, ge=0, le=10**12)
    price_max_minor: int = Field(default=100000, ge=0, le=10**12)
    inventory_min: int = Field(default=0, ge=0, le=10**9)
    inventory_max: int = Field(default=100, ge=0, le=10**9)

    @model_validator(mode="after")
    def check_limits(self):
        """先限制總規模與範圍，避免無效設定進入生成迴圈。"""
        if self.price_min_minor > self.price_max_minor or self.inventory_min > self.inventory_max:
            raise ValueError("Minimum must not exceed maximum")
        if self.product_count * self.variants_per_product > 10000:
            raise ValueError("At most 10000 variants may be generated")
        return self


class Price(SyntheticModel):
    """保留明確幣別與最小單位，避免浮點小數誤差。"""

    currency_code: Literal["usd", "eur", "twd"]
    amount_minor: int = Field(ge=0, le=10**12)


class Product(SyntheticModel):
    """內部商品實體，variant_ids 對應同資料集內的變體。"""

    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    handle: str = Field(min_length=1)
    status: Literal["published"] = "published"
    variant_ids: list[str]


class Variant(SyntheticModel):
    """內部變體包含價格與庫存；H 須另依平台契約映射欄位。"""

    id: str = Field(min_length=1)
    product_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    sku: str = Field(min_length=1)
    inventory_quantity: int = Field(ge=0, le=10**9)
    price: Price


class SyntheticDataset(SyntheticModel):
    """可保存的合成資料集，連同規則、生成器版本與來源標記一起保留。"""

    schema_version: Literal[1] = 1
    config: SyntheticConfig
    namespace: str = Field(pattern=r"^[0-9a-f]{64}$")
    generator_version: str
    provider_version: str
    synthetic_only: Literal[True] = True
    real_data_imported: Literal[False] = False
    products: list[Product]
    variants: list[Variant]

    def to_composition_data(self) -> CompositionData:
        """重建驗證電商快照後輸出通用映射資料，不讓組合器解讀商品模型。"""
        from .generator import checked_dataset

        checked = checked_dataset(self, self.config)
        return CompositionData(scope=checked.config.scope, payload={
            "products": [product.model_dump(mode="json") for product in checked.products],
            "variants": [variant.model_dump(mode="json") for variant in checked.variants],
        })

    @field_validator("synthetic_only", "real_data_imported", mode="before")
    @classmethod
    def check_provenance_type(cls, value):
        """來源標記只接受 JSON boolean，拒絕 1／0 被轉成 True／False。"""
        if type(value) is not bool:
            raise ValueError("Provenance flags must be booleans")
        return value

    @model_validator(mode="after")
    def check_relations(self):
        """檢查唯一性、父子關聯、規模與數值範圍，拒絕孤立或重複實體。"""
        config = self.config
        if len(self.products) != config.product_count:
            raise ValueError("Product count does not match configuration")
        if len(self.variants) != config.product_count * config.variants_per_product:
            raise ValueError("Variant count does not match configuration")
        for values in ([p.id for p in self.products], [p.handle for p in self.products],
                       [v.id for v in self.variants], [v.sku for v in self.variants]):
            if len(values) != len(set(values)):
                raise ValueError("Entity IDs, handles and SKUs must be unique")
        if {p.id for p in self.products} & {v.id for v in self.variants}:
            raise ValueError("Products and variants must not share an ID")
        variants = {variant.id: variant for variant in self.variants}
        referenced = []
        for product in self.products:
            if len(product.variant_ids) != config.variants_per_product:
                raise ValueError("Product variant count does not match configuration")
            for variant_id in product.variant_ids:
                if variant_id not in variants or variants[variant_id].product_id != product.id:
                    raise ValueError("Variant parent or product reference does not match")
                referenced.append(variant_id)
        if len(referenced) != len(set(referenced)) or set(referenced) != set(variants):
            raise ValueError("Duplicate or orphan variant reference")
        for variant in self.variants:
            if not config.inventory_min <= variant.inventory_quantity <= config.inventory_max:
                raise ValueError("Inventory is outside configured bounds")
            if not config.price_min_minor <= variant.price.amount_minor <= config.price_max_minor:
                raise ValueError("Price is outside configured bounds")
            if variant.price.currency_code != config.currency_code:
                raise ValueError("Currency does not match configuration")
        return self


class VerificationReport(SyntheticModel):
    """E 的有效性檢查結果；不表示已通過平台 HTTP 回應契約。"""

    valid: bool
    errors: list[str]
    product_count: int
    variant_count: int
    namespace: str
