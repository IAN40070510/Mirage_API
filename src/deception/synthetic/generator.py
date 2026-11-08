"""E 的確定性資料生成與驗證，不讀取真實商店或呼叫 LLM。"""

import hashlib
import json

from faker import VERSION, Faker

from .models import Product, Price, SyntheticConfig, SyntheticDataset, Variant, VerificationReport

GENERATOR_VERSION = "e-products-v1"
PROVIDER_VERSION = "40.44.0"


class SyntheticError(ValueError):
    """無效設定、資料、隔離身份或產物。"""


def encoded(value) -> bytes:
    """固定 JSON 排序與換行；檔案、雜湊及重建檢查共用同一序列化規則。"""
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")


def namespace_for(config: SyntheticConfig) -> str:
    """把完整設定及生成器／provider 版本納入身份，避免規則改變卻共用資料。"""
    return hashlib.sha256(encoded({"config": config.model_dump(mode="json"),
                                  "generator_version": GENERATOR_VERSION,
                                  "provider_version": PROVIDER_VERSION})).hexdigest()


def _digest(namespace: str, entity: str, index: int) -> str:
    """由資料 namespace、實體種類與索引產生可重現摘要，供 ID 與欄位亂數使用。"""
    return hashlib.sha256(f"{namespace}:{entity}:{index}".encode("ascii")).hexdigest()


def _bounded(namespace: str, field: str, index: int, minimum: int, maximum: int) -> int:
    """用獨立欄位的雜湊產生範圍內整數，避免新增文字欄位改變價格／庫存。"""
    return minimum + int(_digest(namespace, field, index), 16) % (maximum - minimum + 1)


def generate_dataset(config: SyntheticConfig) -> SyntheticDataset:
    """從固定 scope、seed 與規則產生商品／變體；呼叫順序不影響其他資料集。"""
    try:
        if VERSION != PROVIDER_VERSION:
            raise SyntheticError(f"Expected Faker {PROVIDER_VERSION}, found {VERSION}")
        # model_copy 或呼叫者修改 model 不會略過這裡的嚴格設定檢查。
        config = SyntheticConfig.model_validate(config.model_dump(mode="json"))
        namespace = namespace_for(config)
        fake = Faker(config.locale)
        products = []
        variants = []
        for product_index in range(config.product_count):
            product_id = "prod_syn_" + _digest(namespace, "product", product_index)
            # 每個商品重新設定 instance seed，避免全域亂數及查詢順序污染生成結果。
            fake.seed_instance(int(_digest(namespace, "text", product_index), 16))
            title = "Synthetic " + " ".join(fake.words(nb=3))
            variant_ids = []
            for variant_index in range(config.variants_per_product):
                index = product_index * config.variants_per_product + variant_index
                variant_id = "variant_syn_" + _digest(namespace, "variant", index)
                variant_ids.append(variant_id)
                variants.append(Variant(
                    id=variant_id, product_id=product_id, title=f"Synthetic variant {variant_index + 1}",
                    sku="SYN-" + _digest(namespace, "sku", index),
                    inventory_quantity=_bounded(namespace, "inventory", index,
                                                config.inventory_min, config.inventory_max),
                    price=Price(currency_code=config.currency_code, amount_minor=_bounded(
                        namespace, "price", index, config.price_min_minor, config.price_max_minor)),
                ))
            products.append(Product(id=product_id, title=title,
                                    handle=f"synthetic-{namespace}-{product_index + 1}",
                                    variant_ids=variant_ids))
        return SyntheticDataset(config=config, namespace=namespace, generator_version=GENERATOR_VERSION,
                                provider_version=PROVIDER_VERSION, products=products, variants=variants)
    except SyntheticError:
        raise
    except Exception as exc:
        raise SyntheticError(f"Cannot generate dataset: {exc}") from exc


def verify_dataset(dataset: SyntheticDataset, expected_config: SyntheticConfig) -> VerificationReport:
    """先驗證型別及關聯，再完整重建比對，連合法型別但遭改動的欄位也會拒絕。"""
    errors = []
    try:
        checked = SyntheticDataset.model_validate(dataset.model_dump(mode="json"))
        if checked.config != expected_config:
            raise SyntheticError("Dataset configuration does not match expected scope and rules")
        regenerated = generate_dataset(expected_config)
        if encoded(checked.model_dump(mode="json")) != encoded(regenerated.model_dump(mode="json")):
            raise SyntheticError("Dataset does not match deterministic regeneration")
    except Exception as exc:
        errors.append(str(exc))
    # 模型可能已被呼叫者改成無效型別；錯誤報告不能再次因 len(None) 等情況失敗。
    products = getattr(dataset, "products", None)
    variants = getattr(dataset, "variants", None)
    namespace = getattr(dataset, "namespace", None)
    return VerificationReport(valid=not errors, errors=errors,
                              product_count=len(products) if isinstance(products, list) else 0,
                              variant_count=len(variants) if isinstance(variants, list) else 0,
                              namespace=namespace if isinstance(namespace, str) else "")


def checked_dataset(dataset: SyntheticDataset, expected_config: SyntheticConfig) -> SyntheticDataset:
    """所有保存與查詢入口共用驗證，避免無效資料進入後續流程。"""
    report = verify_dataset(dataset, expected_config)
    if not report.valid:
        raise SyntheticError("; ".join(report.errors))
    return SyntheticDataset.model_validate(dataset.model_dump(mode="json"))
