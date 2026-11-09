"""E 合成資料工具的行為驗證；這些內部實體不是完整的平台 HTTP 回應。"""

import json
import random
from pathlib import Path

import pytest
from pydantic import ValidationError

from deception.profile_builder import ProfileTool, build_profile
from deception.profile_builder.models import OperationContext, OperationProfile, ProfileSource
from deception.synthetic import (
    DatasetScope,
    SyntheticConfig,
    SyntheticError,
    SyntheticTool,
    generate_dataset,
    load_dataset,
    save_dataset,
    verify_dataset,
)


def config(**changes):
    """每個測試明確指定隔離身份，避免使用真實網站或顧客資料。"""
    values = {
        "scope": DatasetScope(
            site_id="shop-test", platform_id="medusa", platform_version="2.22.4",
            spec_sha256="a" * 64, scenario_id="product-found", run_id="run-test",
        ),
        "seed": 20261108,
        "product_count": 4,
        "variants_per_product": 3,
    }
    values.update(changes)
    return SyntheticConfig(**values)


def profile_for(scope, **changes):
    """建立只用來檢查身份綁定的 D context，不宣稱通過平台契約。"""
    source = {
        "platform_id": scope.platform_id,
        "platform_version": scope.platform_version,
        "spec_sha256": scope.spec_sha256,
        "source_url": "https://example.org/test-only/openapi.yaml",
        "source_revision": "test-only-fixed-revision",
        "approved": False,
    }
    source.update(changes)
    return OperationContext(
        source=ProfileSource(**source),
        operation=OperationProfile(
            operation_id="getProduct", method="GET", path="/products/{id}",
            schema_pointer="#/paths/~1products~1{id}/get", tags=[], summary=None,
            parameters=[], request_body=None, security=[], responses={"200": {"description": "test"}},
        ),
        specification={"openapi": "3.1.0", "info": {"title": "Test only", "version": "1"}, "paths": {}},
    )


def test_same_configuration_rebuilds_identically_without_global_random_side_effects():
    """確認固定設定可重建相同資料與來源標記，且不改動 Python 全域亂數狀態。"""
    settings = config()
    random.seed(123)
    original_random_state = random.getstate()
    first = generate_dataset(settings)
    assert random.getstate() == original_random_state
    random.random()
    second = generate_dataset(settings)
    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    report = verify_dataset(first, settings)
    assert report.valid, report.errors
    assert report.errors == []
    assert report.product_count == 4
    assert report.variant_count == 12
    assert report.namespace == first.namespace
    assert len(first.namespace) == 64
    assert first.synthetic_only is True
    assert first.real_data_imported is False
    assert first.generator_version
    assert first.provider_version


@pytest.mark.parametrize("field,value", [
    ("site_id", "shop-other"), ("platform_id", "woocommerce"),
    ("platform_version", "other-version"), ("spec_sha256", "b" * 64),
    ("scenario_id", "product-missing"), ("run_id", "run-other"),
])
def test_every_scope_dimension_isolates_ids_and_namespace(field, value):
    """確認任一隔離身份變更都建立不同 namespace，商品與變體 ID 不會混用。"""
    settings = config()
    first = generate_dataset(settings)
    scope_data = settings.scope.model_dump()
    scope_data[field] = value
    second = generate_dataset(config(scope=DatasetScope(**scope_data)))
    assert first.namespace != second.namespace
    assert {p.id for p in first.products}.isdisjoint(p.id for p in second.products)
    assert {v.id for v in first.variants}.isdisjoint(v.id for v in second.variants)


def test_different_seed_isolates_dataset():
    """確認相同隔離範圍下不同 seed 仍產生不同資料身份與內容。"""
    first = generate_dataset(config(seed=1))
    second = generate_dataset(config(seed=2))
    assert first.namespace != second.namespace
    assert first.model_dump() != second.model_dump()


def test_relations_uniqueness_and_generation_ranges():
    """確認商品／變體關聯、ID 與 SKU 唯一性，以及價格和庫存範圍與整數型別。"""
    settings = config(product_count=20, variants_per_product=4, currency_code="twd",
                      inventory_min=0, inventory_max=3, price_min_minor=101, price_max_minor=105)
    dataset = generate_dataset(settings)
    product_ids = {p.id for p in dataset.products}
    variant_ids = {v.id for v in dataset.variants}
    assert len(product_ids) == 20
    assert len(variant_ids) == 80
    assert product_ids.isdisjoint(variant_ids)
    assert len({p.handle for p in dataset.products}) == 20
    assert len({v.sku for v in dataset.variants}) == 80
    by_id = {v.id: v for v in dataset.variants}
    for product in dataset.products:
        assert product.title
        assert len(product.variant_ids) == len(set(product.variant_ids)) == 4
        assert all(by_id[variant_id].product_id == product.id for variant_id in product.variant_ids)
    for variant in dataset.variants:
        assert variant.product_id in product_ids
        assert 0 <= variant.inventory_quantity <= 3
        assert 101 <= variant.price.amount_minor <= 105
        assert variant.price.currency_code == "twd"
        assert type(variant.price.amount_minor) is int
        assert type(variant.inventory_quantity) is int


def test_zero_products_is_a_valid_empty_dataset():
    """確認零商品設定產生可驗證的空快照，查詢介面也正確回傳空結果。"""
    settings = config(product_count=0)
    dataset = generate_dataset(settings)
    assert dataset.products == []
    assert dataset.variants == []
    assert verify_dataset(dataset, settings).valid
    tool = SyntheticTool(dataset, expected_scope=settings.scope)
    assert tool.list_products() == []
    assert tool.get_product("missing") is None
    assert tool.get_variants("missing") == []


def test_fixed_zero_stock_and_zero_price_are_supported():
    """確認價格與庫存上下限皆為零時，生成結果保留合法零值。"""
    dataset = generate_dataset(config(inventory_min=0, inventory_max=0,
                                      price_min_minor=0, price_max_minor=0))
    assert all(v.inventory_quantity == 0 and v.price.amount_minor == 0 for v in dataset.variants)


def test_queries_paginate_and_return_independent_snapshots():
    """確認分頁與關聯查詢結果正確，修改回傳複本不會污染工具保存的資料。"""
    settings = config()
    dataset = generate_dataset(settings)
    tool = SyntheticTool(dataset, expected_scope=settings.scope)
    product = dataset.products[0]
    variant = dataset.variants[0]
    assert [p.id for p in tool.list_products(offset=1, limit=2)] == [p.id for p in dataset.products[1:3]]
    assert tool.list_products(offset=100, limit=2) == []
    assert tool.get_variant(variant.id).product_id == product.id
    assert [v.id for v in tool.get_variants(product.id)] == product.variant_ids

    returned = tool.get_product(product.id)
    returned.variant_ids.clear()
    listed = tool.list_products()
    listed[0].variant_ids.clear()
    returned_variant = tool.get_variant(variant.id)
    returned_variant.price.amount_minor += 1
    assert tool.get_product(product.id).variant_ids == product.variant_ids
    assert tool.get_variant(variant.id).price.amount_minor == variant.price.amount_minor
    assert tool.get_product("not-present") is None
    assert tool.get_variant("not-present") is None
    assert len(tool.list_products()) == settings.product_count


@pytest.mark.parametrize("changes", [
    {"seed": True}, {"product_count": True}, {"product_count": -1},
    {"variants_per_product": 0}, {"inventory_min": -1},
    {"inventory_min": 2, "inventory_max": 1},
    {"price_min_minor": 20, "price_max_minor": 10},
    {"price_min_minor": -1},
])
def test_invalid_generation_rules_are_rejected(changes):
    """確認布林偽整數、負值或顛倒的價格／庫存範圍會在生成前被拒絕。"""
    with pytest.raises((ValidationError, SyntheticError)):
        generate_dataset(config(**changes))


def test_save_and_reload_round_trip_is_deterministic(tmp_path):
    """確認保存路徑依 namespace 定址，載入與重新生成保存均維持相同 bytes。"""
    settings = config()
    dataset = generate_dataset(settings)
    path = save_dataset(dataset, tmp_path)
    assert path == tmp_path / "synthetic_data" / "medusa" / f"{dataset.namespace}.json"
    encoded = path.read_bytes()
    assert load_dataset(path, settings) == dataset
    assert save_dataset(generate_dataset(settings), tmp_path).read_bytes() == encoded


def test_loading_with_another_configuration_is_rejected(tmp_path):
    """確認載入工具不會用另一份 seed 或設定接受既有合成資料檔。"""
    path = save_dataset(generate_dataset(config()), tmp_path)
    with pytest.raises(SyntheticError):
        load_dataset(path, config(seed=99))


@pytest.mark.parametrize("change", ["title", "relation", "namespace", "provider_version"])
def test_validly_typed_but_tampered_data_is_rejected(tmp_path, change):
    """確認文字、關聯、namespace 或 provider 版本遭改寫時，即使 JSON 可解析仍拒絕載入。"""
    settings = config()
    dataset = generate_dataset(settings)
    path = save_dataset(dataset, tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if change == "title":
        data["products"][0]["title"] = "Changed title"
    elif change == "relation":
        data["variants"][0]["product_id"] = "missing-product"
    elif change == "namespace":
        data["namespace"] = "0" * 64
    else:
        data["provider_version"] = "unmatched-version"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(SyntheticError):
        load_dataset(path, settings)


def test_verification_reports_failure_and_save_rejects_changed_data(tmp_path):
    """確認資料內容偏離種子重建結果時，驗證回報錯誤且保存入口拒絕寫入。"""
    settings = config()
    dataset = generate_dataset(settings)
    dataset.products[0].title = "Valid string but not generated from this seed"
    report = verify_dataset(dataset, settings)
    assert not report.valid
    assert report.errors
    with pytest.raises(SyntheticError):
        save_dataset(dataset, tmp_path)


@pytest.mark.parametrize("field", ["products", "variants", "namespace"])
def test_verification_returns_report_even_after_invalid_in_memory_mutation(field):
    """可變模型遭破壞時，驗證本身也必須可靠回報失敗。"""
    settings = config()
    dataset = generate_dataset(settings)
    setattr(dataset, field, None)
    report = verify_dataset(dataset, settings)
    assert report.valid is False
    assert report.errors


@pytest.mark.parametrize("field,value", [("synthetic_only", 1), ("real_data_imported", 0),
                                         ("schema_version", True)])
def test_provenance_and_schema_version_do_not_coerce_scalar_types(field, value):
    """即使 Python 的 1 == True，產物的來源標記及版本仍須保留嚴格型別。"""
    from deception.synthetic import SyntheticDataset

    data = generate_dataset(config()).model_dump(mode="json")
    data[field] = value
    with pytest.raises(ValidationError):
        SyntheticDataset.model_validate(data)


def test_tool_rejects_wrong_scope():
    """確認查詢工具不能以另一站點的隔離身份包裝同一份資料快照。"""
    settings = config()
    scope_data = settings.scope.model_dump()
    scope_data["site_id"] = "another-shop"
    with pytest.raises(SyntheticError):
        SyntheticTool(generate_dataset(settings), expected_scope=DatasetScope(**scope_data))


@pytest.mark.parametrize("changes", [
    {"platform_id": "woocommerce"}, {"platform_version": "wrong-version"},
    {"spec_sha256": "b" * 64},
])
def test_d_profile_identity_must_match(changes):
    """確認綁定 D 時平台、版本與規格 hash 都必須吻合 E 的預期 scope。"""
    settings = config()
    dataset = generate_dataset(settings)
    with pytest.raises(SyntheticError):
        SyntheticTool(dataset, expected_scope=settings.scope, profile=profile_for(settings.scope, **changes))


def test_d_profile_identity_binding_does_not_promote_source_approval():
    """確認 D/E 身份相符可供內部查詢，但不會因此提升 D 來源核准狀態。"""
    settings = config()
    dataset = generate_dataset(settings)
    profile = profile_for(settings.scope)
    tool = SyntheticTool(dataset, expected_scope=settings.scope, profile=profile)
    assert tool.get_product(dataset.products[0].id).id == dataset.products[0].id
    assert profile.source.approved is False


def test_medusa_source_to_profile_to_persisted_synthetic_query(tmp_path):
    """使用 repo 真實來源做離線 D/E 閉環，仍不將內部實體當成 Medusa 完整回應。"""
    source = Path(__file__).resolve().parents[1] / "domains/ecommerce/inputs/sources/medusa/source.yaml"
    generated = tmp_path / "generated"
    profile = build_profile(source, generated)
    context = ProfileTool(generated).get_operation(
        platform_id=profile.source.platform_id,
        platform_version=profile.source.platform_version,
        spec_sha256=profile.source.spec_sha256,
        method="GET", path="/store/products/{id}", allow_unreviewed=True,
    )
    scope = DatasetScope(
        site_id="medusa-offline-test", platform_id=context.source.platform_id,
        platform_version=context.source.platform_version, spec_sha256=context.source.spec_sha256,
        scenario_id="product-found", run_id="integration-test",
    )
    settings = config(scope=scope, product_count=3, variants_per_product=2)
    dataset = generate_dataset(settings)
    assert verify_dataset(dataset, settings).valid
    path = save_dataset(dataset, generated)
    restored = load_dataset(path, settings)
    tool = SyntheticTool(restored, expected_scope=scope, profile=context)

    product = tool.get_product(restored.products[0].id)
    variants = tool.get_variants(product.id)
    assert len(variants) == 2
    assert product.variant_ids == [variant.id for variant in variants]
    assert all(variant.product_id == product.id for variant in variants)
    assert restored.config.scope.platform_id == context.source.platform_id == "medusa"
    assert restored.config.scope.platform_version == context.source.platform_version
    assert restored.config.scope.spec_sha256 == context.source.spec_sha256
    assert context.operation.operation_id == "GetProductsId"
    assert context.source.approved is False
    assert profile.source.approved is False

    # 即使另一份 context 有相同平台與版本，契約雜湊不同也必須拒絕跨規格綁定。
    changed_context = context.model_copy(deep=True)
    changed_context.source.spec_sha256 = "0" * 64
    with pytest.raises(SyntheticError):
        SyntheticTool(restored, expected_scope=scope, profile=changed_context)
