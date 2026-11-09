"""H 的候選回應組合與 D/E/I 整合驗證；合成測試不代表官方服務相容。"""

import hashlib
import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
import yaml

from deception.core import CompositionError, CompositionPlan, DataBinding, ResponseComposer
from deception.common import CompositionData
from deception.profile_builder import build_profile
from deception.synthetic import DatasetScope, SyntheticConfig, generate_dataset
from mirage_validator.gate import OfficialResponseGate, PlatformRegistry


def source_package(root, *, version="3.1.0", approved=True, change=None):
    """建立有固定雜湊的測試規格；核准狀態僅適用這份合成契約。"""
    root.mkdir(parents=True, exist_ok=True)
    product = {"type": "object", "required": ["id", "title"], "additionalProperties": False,
               "properties": {"id": {"type": "string"}, "title": {"type": "string"}}}
    spec = {"openapi": version, "info": {"title": "Synthetic composer test", "version": "1.2.3"},
            "paths": {"/products/{id}": {"get": {"operationId": "getProduct", "parameters": [
                {"in": "path", "name": "id", "required": True, "schema": {"type": "string"}}],
                "responses": {
                    "200": {"description": "Product", "content": {"application/json": {"schema": {
                        "type": "object", "required": ["product"], "additionalProperties": False,
                        "properties": {"product": {"$ref": "#/components/schemas/Product"}}}}}},
                    "404": {"description": "Not found", "content": {"application/json": {"schema": {
                        "type": "object", "required": ["type", "message"], "additionalProperties": False,
                        "properties": {"type": {"enum": ["not_found"]}, "message": {"type": "string"}}}}}},
                    "204": {"description": "No response schema"},
                }}}}, "components": {"schemas": {"Product": product}}}
    if change:
        change(spec)
    data = yaml.safe_dump(spec, sort_keys=False).encode("utf-8")
    (root / "openapi.yaml").write_bytes(data)
    source = {"schema_version": 1, "platform_id": "synthetic", "platform_version": "1.2.3",
              "source_url": "https://example.org/test-only/openapi.yaml", "source_revision": "test-only-fixed",
              "spec_sha256": hashlib.sha256(data).hexdigest(), "approved": approved, "openapi_file": "openapi.yaml"}
    source_path = root / "source.yaml"
    source_path.write_text(yaml.safe_dump(source), encoding="utf-8")
    return source_path, source, data


def setup_composer(tmp_path, **changes):
    """建立 D 產物、固定 E 快照與相符 scope，回傳可供 H/I 整合測試使用的工具。"""
    source_path, source, data = source_package(tmp_path / "source", **changes)
    output = tmp_path / "generated"
    build_profile(source_path, output)
    scope = DatasetScope(site_id="shop-test", platform_id=source["platform_id"],
                         platform_version=source["platform_version"], spec_sha256=source["spec_sha256"],
                         scenario_id="product-found", run_id="composer-test")
    dataset = generate_dataset(SyntheticConfig(scope=scope, seed=42, product_count=2, variants_per_product=1))
    return ResponseComposer(output), scope, dataset, source, data


def plan_for(scope, **changes):
    """由明確 placeholder 與綁定規則組合 E 商品，沒有缺值補猜測的規則。"""
    values = {"scope": scope, "method": "GET", "path": "/products/{id}", "status_code": 200,
              "body": {"product": {"id": "", "title": ""}},
              "bindings": [DataBinding(source_pointer="/products/0/id", target_pointer="/product/id"),
                           DataBinding(source_pointer="/products/0/title", target_pointer="/product/title")]}
    values.update(changes)
    return CompositionPlan(**values)


def gate_for(root, source, data, *, approved=True, base="https://shop.test"):
    """讓 I 讀取相同 bytes，部署核准只作用於臨時合成測試站點。"""
    directory = root / "contract"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "openapi.yaml").write_bytes(data)
    manifest = {key: source[key] for key in ("platform_id", "platform_version", "source_url",
                                            "source_revision", "spec_sha256")}
    manifest.update(approved=approved, openapi_file="openapi.yaml", base_urls=[base], query_contexts=[{}])
    (directory / "manifest.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    return OfficialResponseGate(PlatformRegistry(root))


@pytest.mark.parametrize("version", ["3.0.3", "3.1.0"])
def test_d_e_h_i_preserves_exact_candidate_and_passes_synthetic_contract(tmp_path, version):
    """確認 D/E/H/I 交接保留同一份候選 triple 與身份，且不修改原計畫或資料快照。"""
    composer, scope, dataset, source, data = setup_composer(tmp_path, version=version)
    plan = plan_for(scope, headers={"X-Synthetic-Trace": "test-001"})
    original_plan = plan.model_dump(mode="json")
    original_dataset = dataset.model_dump(mode="json")
    candidate = composer.compose(plan, dataset=dataset)
    assert candidate.status_code == 200
    assert json.loads(candidate.body) == {"product": {"id": dataset.products[0].id,
                                                      "title": dataset.products[0].title}}
    assert candidate.body_bytes == candidate.body.encode("utf-8")
    assert dict(candidate.headers)["X-Synthetic-Trace"] == "test-001"
    assert candidate.identity.platform_id == scope.platform_id
    assert candidate.identity.platform_version == scope.platform_version
    assert candidate.identity.spec_sha256 == scope.spec_sha256
    assert candidate.identity.site_id == scope.site_id
    assert candidate.identity.scenario_id == scope.scenario_id
    assert candidate.identity.run_id == scope.run_id
    assert candidate.identity.operation_id == "getProduct"
    assert candidate.identity.source_approved is True
    request = candidate.to_gate_request("https://shop.test/products/" + dataset.products[0].id)
    assert request.body == candidate.body
    assert request.status_code == candidate.status_code
    assert request.headers == dict(candidate.headers)
    result = gate_for(tmp_path / "gate", source, data).validate(request)
    assert result.decision == "pass", result
    assert plan.model_dump(mode="json") == original_plan
    assert dataset.model_dump(mode="json") == original_dataset


def test_explicit_404_body_passes_same_contract_without_dataset(tmp_path):
    """確認不使用 E 映射的明確 404 JSON body 可依同一操作契約組合並通過 I。"""
    composer, scope, _, source, data = setup_composer(tmp_path)
    candidate = composer.compose(plan_for(scope, status_code=404, bindings=[],
                                         body={"type": "not_found", "message": "Synthetic product not found"}))
    result = gate_for(tmp_path / "gate", source, data).validate(
        candidate.to_gate_request("https://shop.test/products/not-found"))
    assert result.valid, result
    assert candidate.status_code == 404


def test_candidate_and_identity_are_frozen_and_detached_from_inputs(tmp_path):
    """確認候選及身份不可賦值修改，外部模板或 E 資料變動也不影響已序列化 body。"""
    composer, scope, dataset, _, _ = setup_composer(tmp_path)
    plan = plan_for(scope)
    candidate = composer.compose(plan, dataset=dataset)
    original_body = candidate.body
    with pytest.raises(FrozenInstanceError):
        candidate.body = "changed"
    with pytest.raises(FrozenInstanceError):
        candidate.identity.run_id = "changed"
    plan.body["product"]["title"] = "Changed template"
    dataset.products[0].title = "Changed E data"
    assert candidate.body == original_body
    assert isinstance(candidate.headers, tuple)


def test_composition_is_deterministic_and_keeps_unicode(tmp_path):
    """確認相同明確指令產生相同候選 bytes，並保留原始 Unicode 文字。"""
    composer, scope, _, _, _ = setup_composer(tmp_path)
    plan = plan_for(scope, bindings=[], body={"product": {"id": "prod-test", "title": "合成商品"}})
    first = composer.compose(plan)
    second = composer.compose(plan)
    assert first == second
    assert first.body_bytes == second.body_bytes
    assert "合成商品" in first.body


def test_composition_dto_rejects_a_different_run_scope(tmp_path):
    """通用資料格式不能繞過 run 隔離，其他執行的正確商品仍須拒絕。"""
    composer, scope, dataset, _, _ = setup_composer(tmp_path)
    projection = dataset.to_composition_data()
    projection.scope.run_id = "different-run"
    with pytest.raises(CompositionError) as error:
        composer.compose(plan_for(scope), dataset=projection)
    assert error.value.code == "scope_mismatch"


def test_composition_dto_revalidates_mutated_payload_before_accepting_a_candidate(tmp_path):
    """領域投影被修改為違反回應契約的型別後，不得以既有 DTO 身份放行。"""
    composer, scope, dataset, _, _ = setup_composer(tmp_path)
    projection = dataset.to_composition_data()
    projection.payload["products"][0]["id"] = 123
    with pytest.raises(CompositionError) as error:
        composer.compose(plan_for(scope), dataset=projection)
    assert error.value.code == "contract_mismatch"


def test_composition_adapter_must_return_the_explicit_dto(tmp_path):
    """未宣告 adapter 的字典及回傳裸字典的 adapter 都不是可接受的權威映射輸入。"""
    composer, scope, dataset, _, _ = setup_composer(tmp_path)
    projection = dataset.to_composition_data()

    class DictionaryAdapter:
        """故意違反投影介面，驗證組合器不會隱含信任任意字典。"""

        def to_composition_data(self):
            """回傳裸字典作為錯誤測試輸入，不能被隱含轉成已驗證 DTO。"""
            return projection.model_dump(mode="json")

    for value in (projection.model_dump(mode="json"), DictionaryAdapter(), object()):
        with pytest.raises(CompositionError) as error:
            composer.compose(plan_for(scope), dataset=value)
        assert error.value.code == "invalid_dataset"
    assert isinstance(projection, CompositionData)


@pytest.mark.parametrize("changes", [
    {"status_code": 201}, {"status_code": 204, "body": None, "bindings": []},
    {"media_type": "text/plain"}, {"media_type": "application/json; charset=iso-8859-1"},
    {"path": "/products/actual-id"}, {"method": "DELETE"},
    {"bindings": [], "body": {"product": {"id": "prod-test", "title": 123}}},
    {"bindings": [], "body": {"product": {"id": "prod-test"}}},
    {"bindings": [], "body": {"product": {"id": "prod-test", "title": "test", "extra": True}}},
])
def test_unsupported_or_invalid_candidates_are_rejected_without_repair(tmp_path, changes):
    """確認未支援方法／媒體、錯誤狀態或 body 契約違規都直接拒絕，不自動修正。"""
    composer, scope, dataset, _, _ = setup_composer(tmp_path)
    with pytest.raises(CompositionError):
        composer.compose(plan_for(scope, **changes), dataset=dataset)


@pytest.mark.parametrize("headers", [
    {"Content-Type": "text/plain"}, {"X-Trace": "one\r\ntwo"}, {"X-Bad\nName": "value"},
    {"X-Test": "one", "x-test": "two"}, {"Content-Length": "1"},
    {"Transfer-Encoding": "chunked"}, {"Connection": "close"},
])
def test_headers_do_not_allow_ambiguity_injection_or_transport_override(tmp_path, headers):
    """確認 header 注入、大小寫重複、Content-Type 衝突與傳輸層覆寫均被拒絕。"""
    composer, scope, dataset, _, _ = setup_composer(tmp_path)
    with pytest.raises(CompositionError):
        composer.compose(plan_for(scope, headers=headers), dataset=dataset)


@pytest.mark.parametrize("bindings", [
    [DataBinding(source_pointer="/products/99/id", target_pointer="/product/id")],
    [DataBinding(source_pointer="/products/0/id", target_pointer="/product/missing")],
    [DataBinding(source_pointer="/config/seed", target_pointer="/product/id")],
    [DataBinding(source_pointer="/products/0/id", target_pointer="/product/id"),
     DataBinding(source_pointer="/products/1/id", target_pointer="/product/id")],
    [DataBinding(source_pointer="/products/0", target_pointer="/product"),
     DataBinding(source_pointer="/products/0/id", target_pointer="/product/id")],
])
def test_bindings_require_explicit_existing_nonoverlapping_targets(tmp_path, bindings):
    """確認映射來源及目標須存在且互不重疊，不能讀取 E 的設定或建立錯誤欄位。"""
    composer, scope, dataset, _, _ = setup_composer(tmp_path)
    with pytest.raises(CompositionError):
        composer.compose(plan_for(scope, bindings=bindings), dataset=dataset)


def test_binding_requires_dataset_and_matching_scope(tmp_path):
    """確認有 E 映射時必須提供資料，且資料與指令的完整隔離 scope 相符。"""
    composer, scope, dataset, _, _ = setup_composer(tmp_path)
    with pytest.raises(CompositionError):
        composer.compose(plan_for(scope))
    other = scope.model_copy(update={"site_id": "other-shop"})
    with pytest.raises(CompositionError):
        composer.compose(plan_for(other), dataset=dataset)


def test_unreviewed_source_requires_explicit_preview_and_remains_unapproved(tmp_path):
    """確認未審來源只可顯式預覽，成功組合也仍保留未審查身份。"""
    composer, scope, dataset, _, _ = setup_composer(tmp_path, approved=False)
    with pytest.raises(CompositionError):
        composer.compose(plan_for(scope), dataset=dataset)
    candidate = composer.compose(plan_for(scope), dataset=dataset, allow_unreviewed=True)
    assert candidate.identity.source_approved is False


def test_real_medusa_404_preflight_does_not_approve_source_or_deployment(tmp_path):
    """讀現有來源驗證404格式；I仍應拒絕未審規格，不能把preflight當正式pass。"""
    source_path = Path(__file__).resolve().parents[1] / "domains/ecommerce/inputs/sources/medusa/source.yaml"
    output = tmp_path / "generated"
    profile = build_profile(source_path, output)
    source = profile.source
    scope = DatasetScope(site_id="medusa-offline-test", platform_id=source.platform_id,
                         platform_version=source.platform_version, spec_sha256=source.spec_sha256,
                         scenario_id="product-missing", run_id="composer-test")
    candidate = ResponseComposer(output).compose(
        CompositionPlan(scope=scope, method="GET", path="/store/products/{id}", status_code=404,
                        body={"type": "not_found", "message": "Synthetic product not found"}),
        allow_unreviewed=True,
    )
    assert candidate.identity.source_approved is False
    data = (source_path.parent / source.openapi_file).read_bytes()
    result = gate_for(tmp_path / "gate", source.model_dump(), data, approved=False,
                      base="https://shop.example").validate(
        candidate.to_gate_request("https://shop.example/store/products/not-found"))
    assert result.valid is False
    assert result.decision == "unverifiable"
    assert result.errors[0].code == "contract_not_approved"


@pytest.mark.parametrize("status", [206, 418])
def test_status_range_and_default_response_selection_match_i(tmp_path, status):
    """H 與 I 必須使用相同的明確狀態／狀態範圍／default 選擇規則。"""
    def change(spec):
        """把成功與錯誤回應分別移為 2XX 與 default，建立狀態選擇優先序案例。"""
        responses = spec["paths"]["/products/{id}"]["get"]["responses"]
        responses["2XX"] = responses.pop("200")
        responses["default"] = responses.pop("404")

    composer, scope, dataset, source, data = setup_composer(tmp_path, change=change)
    settings = {} if status == 206 else {
        "bindings": [], "body": {"type": "not_found", "message": "Synthetic error"}}
    candidate = composer.compose(plan_for(scope, status_code=status, **settings), dataset=dataset)
    result = gate_for(tmp_path / "gate", source, data).validate(
        candidate.to_gate_request("https://shop.test/products/example"))
    assert result.valid, result
    assert candidate.status_code == status


def test_required_response_header_is_case_insensitive_and_validated(tmp_path):
    """確認必填 header 名稱不分大小寫，但其數值仍須符合原契約型別。"""
    def change(spec):
        """加入必填整數 X-Count 回應 header，涵蓋缺值、錯型與合法值。"""
        response = spec["paths"]["/products/{id}"]["get"]["responses"]["200"]
        response["headers"] = {"X-Count": {"required": True, "schema": {"type": "integer"}}}

    composer, scope, dataset, source, data = setup_composer(tmp_path, change=change)
    with pytest.raises(CompositionError):
        composer.compose(plan_for(scope), dataset=dataset)
    with pytest.raises(CompositionError):
        composer.compose(plan_for(scope, headers={"X-COUNT": "not-a-number"}), dataset=dataset)
    candidate = composer.compose(plan_for(scope, headers={"X-COUNT": "3"}), dataset=dataset)
    assert dict(candidate.headers)["X-COUNT"] == "3"
    result = gate_for(tmp_path / "gate", source, data).validate(
        candidate.to_gate_request("https://shop.test/products/example"))
    assert result.valid, result


def test_json_schema_false_rejects_and_empty_schema_is_not_missing(tmp_path):
    """3.1 布林 false 是禁止任何 body；空 schema 則允許任意 JSON，兩者都不是缺規格。"""
    def change(spec):
        """分別設定 false 與空 schema，區分禁止內容及允許任意內容的回應契約。"""
        responses = spec["paths"]["/products/{id}"]["get"]["responses"]
        responses["200"]["content"]["application/json"]["schema"] = False
        responses["404"]["content"]["application/json"]["schema"] = {}

    composer, scope, _, _, _ = setup_composer(tmp_path, change=change)
    with pytest.raises(CompositionError) as failure:
        composer.compose(plan_for(scope, bindings=[], body=None))
    assert failure.value.code == "contract_mismatch"
    candidate = composer.compose(plan_for(scope, status_code=404, bindings=[], body=None))
    assert candidate.body == "null"


@pytest.mark.parametrize("body", [None, {"arbitrary": [1, True, "text"]}])
def test_json_schema_true_accepts_any_json_body(tmp_path, body):
    """3.1 true 適配不可繞過 header 檢查或改寫來源，只允許原 schema 已允許的 JSON。"""
    def change(spec):
        """設定 literal true body 及必填整數 header，以檢查兩種驗證路徑仍各自生效。"""
        response = spec["paths"]["/products/{id}"]["get"]["responses"]["200"]
        response["content"]["application/json"]["schema"] = True
        response["headers"] = {"X-Count": {"required": True, "schema": {"type": "integer"}}}

    composer, scope, _, source, raw_spec = setup_composer(tmp_path, change=change)
    candidate = composer.compose(plan_for(scope, bindings=[], body=body, headers={"X-Count": "3"}))
    assert json.loads(candidate.body) == body
    assert candidate.identity.spec_sha256 == source["spec_sha256"]
    with pytest.raises(CompositionError):
        composer.compose(plan_for(scope, bindings=[], body=body))
    with pytest.raises(CompositionError):
        composer.compose(plan_for(scope, bindings=[], body=body, headers={"X-Count": "invalid"}))
    assert (tmp_path / "source/openapi.yaml").read_bytes() == raw_spec
    snapshot = tmp_path / "generated/schemas/synthetic" / (source["spec_sha256"] + ".yaml")
    assert snapshot.read_bytes() == raw_spec


@pytest.mark.parametrize("value", [True, "3"])
def test_body_json_types_are_not_cast_to_schema_integer(tmp_path, value):
    """確認 JSON 布林與字串不會被轉成契約整數，合法整數則保持原始型別。"""
    def change(spec):
        """將商品 ID 契約改為整數，建立原始 JSON 型別不可隱含轉換的案例。"""
        spec["components"]["schemas"]["Product"]["properties"]["id"] = {"type": "integer"}

    composer, scope, _, _, _ = setup_composer(tmp_path, change=change)
    with pytest.raises(CompositionError):
        composer.compose(plan_for(scope, bindings=[], body={"product": {"id": value, "title": "test"}}))
    candidate = composer.compose(plan_for(scope, bindings=[], body={"product": {"id": 3, "title": "test"}}))
    assert json.loads(candidate.body)["product"]["id"] == 3
    assert type(json.loads(candidate.body)["product"]["id"]) is int


@pytest.mark.parametrize("header_body", ["wrong", True])
def test_true_body_schema_still_validates_header_content_schema(tmp_path, header_body):
    """body 的 true adapter 不能略過共用解析路徑中的 header JSON schema。"""
    def change(spec):
        """設定不限制 body 的 schema 與帶 JSON 整數內容契約的 X-Count header。"""
        response = spec["paths"]["/products/{id}"]["get"]["responses"]["200"]
        response["content"]["application/json"]["schema"] = True
        response["headers"] = {
            "X-Count": {"required": True, "content": {
                "application/json": {"schema": {"type": "integer"}}}},
        }

    composer, scope, _, _, _ = setup_composer(tmp_path, change=change)
    with pytest.raises(CompositionError):
        composer.compose(plan_for(scope, bindings=[], body=None,
                                  headers={"X-Count": json.dumps(header_body)}))
    candidate = composer.compose(plan_for(scope, bindings=[], body=None, headers={"X-Count": "3"}))
    assert candidate.body == "null"
    assert dict(candidate.headers)["X-Count"] == "3"


def test_binding_json_pointer_escapes_and_array_indexes(tmp_path):
    """Binding 使用字串 JSON Pointer；escaped key 有意義，負索引與前導零不可接受。"""
    def change(spec):
        """建立包含斜線與波浪號的 JSON key，驗證 Pointer escape 能正確定位目標。"""
        spec["paths"]["/products/{id}"]["get"]["responses"]["200"]["content"]["application/json"]["schema"] = {
            "type": "object", "properties": {"a/b": {"type": "object", "properties": {"~id": {"type": "string"}}}}}

    composer, scope, dataset, _, _ = setup_composer(tmp_path, change=change)
    candidate = composer.compose(plan_for(scope, body={"a/b": {"~id": ""}}, bindings=[
        DataBinding(source_pointer="/products/0/id", target_pointer="/a~1b/~0id")]), dataset=dataset)
    assert json.loads(candidate.body)["a/b"]["~id"] == dataset.products[0].id
    for source_pointer in ("/products/-1/id", "/products/00/id", "/products/0/~2id"):
        with pytest.raises(CompositionError):
            composer.compose(plan_for(scope, body={"a/b": {"~id": ""}}, bindings=[
                DataBinding(source_pointer=source_pointer, target_pointer="/a~1b/~0id")]), dataset=dataset)


def explicit_medusa_product_fixture():
    """手寫的契約測試值；deleted_at 固定時間僅驗證本地 schema，不證明實際刪除語意。"""
    variant = {
        "options": [], "title": "", "id": "", "created_at": "2020-01-01T00:00:00Z",
        "updated_at": "2020-01-01T00:00:00Z", "thumbnail": "", "width": 0, "weight": 0,
        "length": 0, "height": 0, "origin_country": "TW", "hs_code": "synthetic",
        "mid_code": "synthetic", "material": "synthetic", "deleted_at": "2020-01-01T00:00:00Z",
        "manage_inventory": True, "allow_backorder": False, "sku": "", "ean": "synthetic",
        "upc": "synthetic", "barcode": "synthetic", "product_id": "",
    }
    return {"product": {
        "variants": [variant], "options": [], "images": [], "length": 0, "title": "",
        "status": "published", "description": "Explicit synthetic contract fixture", "id": "",
        "created_at": "2020-01-01T00:00:00Z", "updated_at": "2020-01-01T00:00:00Z", "subtitle": "",
        "thumbnail": "", "handle": "", "is_giftcard": False, "width": 0, "weight": 0, "height": 0,
        "origin_country": "TW", "hs_code": "synthetic", "mid_code": "synthetic", "material": "synthetic",
        "collection_id": "col-synthetic", "type_id": "type-synthetic", "discountable": False,
        "external_id": "external-synthetic", "deleted_at": "2020-01-01T00:00:00Z",
    }}


def test_real_medusa_200_explicit_fixture_maps_e_and_rejects_missing_field(tmp_path):
    """實際來源的200必填值全部明確提供；H不補猜缺值，也不提升來源核准狀態。"""
    source_path = Path(__file__).resolve().parents[1] / "domains/ecommerce/inputs/sources/medusa/source.yaml"
    output = tmp_path / "generated"
    profile = build_profile(source_path, output)
    source = profile.source
    scope = DatasetScope(site_id="medusa-offline-test", platform_id=source.platform_id,
                         platform_version=source.platform_version, spec_sha256=source.spec_sha256,
                         scenario_id="product-found", run_id="composer-test")
    dataset = generate_dataset(SyntheticConfig(scope=scope, seed=42, product_count=1, variants_per_product=1))
    bindings = [DataBinding(source_pointer=f"/products/0/{field}", target_pointer=f"/product/{field}")
                for field in ("id", "title", "handle", "status")]
    bindings += [DataBinding(source_pointer=f"/variants/0/{field}", target_pointer=f"/product/variants/0/{field}")
                 for field in ("id", "title", "sku", "product_id")]
    body = explicit_medusa_product_fixture()
    plan = CompositionPlan(scope=scope, path="/store/products/{id}", status_code=200, body=body, bindings=bindings)
    composer = ResponseComposer(output)
    candidate = composer.compose(plan, dataset=dataset, allow_unreviewed=True)
    product = json.loads(candidate.body)["product"]
    assert product["id"] == dataset.products[0].id
    assert product["variants"][0]["id"] == dataset.variants[0].id
    assert product["variants"][0]["product_id"] == product["id"]
    assert "inventory_quantity" not in product["variants"][0]
    assert "calculated_price" not in product["variants"][0]
    assert candidate.identity.source_approved is False
    del plan.body["product"]["deleted_at"]
    with pytest.raises(CompositionError):
        composer.compose(plan, dataset=dataset, allow_unreviewed=True)
