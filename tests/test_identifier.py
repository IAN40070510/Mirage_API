"""B 的部署／契約識別測試；使用臨時合成規格，不核准任何實際平台。"""

import copy
import hashlib
from urllib.parse import parse_qsl, unquote, urlsplit

import pytest
import yaml

from deception.api.ingress import NormalizedRequest
from deception.discovery import BindingConfig, DeploymentBinding, PlatformIdentifier, RuntimeContext
from mirage_validator.gate import GateRequest, OfficialResponseGate, PlatformRegistry


def source_package(root, *, folder="test", base="https://shop.test/api", approved=True,
                   platform_version="1.0", contexts=None, change=None):
    """建立固定雜湊與明確部署 URL 的測試契約。"""
    directory = root / folder
    directory.mkdir(parents=True, exist_ok=True)
    response = {"description": "Synthetic test only", "content": {"application/json": {"schema": {
        "type": "object", "required": ["id"], "properties": {"id": {"type": "string"}},
        "additionalProperties": False}}}}
    spec = {"openapi": "3.1.0", "info": {"title": "Identifier test only", "version": "1"},
            "paths": {"/products/{id}": {"get": {"operationId": "getProduct", "parameters": [
                {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {"200": response}}}}}
    if change:
        change(spec)
    raw = yaml.safe_dump(spec).encode("utf-8")
    (directory / "openapi.yaml").write_bytes(raw)
    manifest = {"platform_id": "synthetic", "platform_version": platform_version,
                "source_url": "https://example.org/test-only", "source_revision": "test-only-fixed",
                "spec_sha256": hashlib.sha256(raw).hexdigest(), "approved": approved,
                "openapi_file": "openapi.yaml", "base_urls": [base],
                "query_contexts": [{}] if contexts is None else contexts}
    (directory / "manifest.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    return manifest


def binding_for(manifest, **changes):
    values = {"binding_id": "shop-binding", "environment_id": "test-env", "deployment_id": "test-deploy",
              "service_id": "store", "site_id": "shop-test", "base_url": manifest["base_urls"][0],
              "platform_id": manifest["platform_id"], "platform_version": manifest["platform_version"],
              "spec_sha256": manifest["spec_sha256"], "enabled": True}
    values.update(changes)
    return DeploymentBinding(**values)


def identifier(root, manifest, **changes):
    return PlatformIdentifier(PlatformRegistry(root), BindingConfig(bindings=[binding_for(manifest, **changes)]))


def gate_request(url, method="GET"):
    return GateRequest(request_url=url, request_method=method, status_code=200,
                       headers={"Content-Type": "application/json"}, body='{"id":"synthetic-product"}')


def assert_failure(result, code):
    assert result.decision == "unverifiable", result
    assert result.errors and result.errors[0].code == code, result


def normalized(url, *, headers=None):
    """保留 A 的 raw URL 與已解碼 path，供 percent-encoding 一致性測試。"""
    parts = urlsplit(url)
    return NormalizedRequest(request_id="identifier-test-001", method="GET", raw_url=url,
                             path=unquote(parts.path), raw_path=parts.path.encode("ascii"),
                             query_string=parts.query.encode("ascii"),
                             query=tuple(parse_qsl(parts.query, keep_blank_values=True)),
                             headers=(("host", parts.netloc),) if headers is None else headers, body=b"")


def test_identifies_explicit_deployment_and_same_operation_as_i(tmp_path):
    manifest = source_package(tmp_path)
    result = identifier(tmp_path, manifest).identify("https://shop.test/api/products/prod-1", "GET")
    assert result.decision == "identified", result
    identity = result.identity
    assert (identity.environment_id, identity.deployment_id, identity.service_id) == ("test-env", "test-deploy", "store")
    assert identity.site_id == "shop-test"
    assert identity.binding_id == "shop-binding"
    assert identity.base_url == "https://shop.test/api"
    assert identity.operation_id == "getProduct"
    assert identity.path == "/products/{id}"
    assert identity.path_parameters == {"id": "prod-1"}
    assert identity.query == {}
    assert identity.profile_arguments() == {"platform_id": "synthetic", "platform_version": "1.0",
                                            "spec_sha256": manifest["spec_sha256"], "method": "GET",
                                            "path": "/products/{id}"}
    checked = OfficialResponseGate(PlatformRegistry(tmp_path)).validate(gate_request("https://shop.test/api/products/prod-1"))
    assert checked.valid, checked
    assert (checked.platform_id, checked.platform_version, checked.spec_sha256, checked.operation_id) == (
        identity.platform_id, identity.platform_version, identity.spec_sha256, identity.operation_id)


@pytest.mark.parametrize("url", ["https://unknown.test/api/products/1", "https://shop.test/apix/products/1",
                                  "http://shop.test/api/products/1", "https://shop.test:443/api/products/1"])
def test_binding_requires_exact_origin_and_prefix_boundary(tmp_path, url):
    manifest = source_package(tmp_path)
    assert_failure(identifier(tmp_path, manifest).identify(url, "GET"), "binding_not_unique")


@pytest.mark.parametrize("url,method", [("https://shop.test/api/orders/1", "GET"),
                                       ("https://shop.test/api/products/1", "POST"),
                                       ("https://shop.test/api/products/1", "HEAD"),
                                       ("https://shop.test/api/products/1/", "GET")])
def test_unknown_route_method_and_trailing_slash_are_not_inferred(tmp_path, url, method):
    manifest = source_package(tmp_path)
    assert_failure(identifier(tmp_path, manifest).identify(url, method), "operation_not_unique")


def test_unsupported_method_is_explicit(tmp_path):
    manifest = source_package(tmp_path)
    assert_failure(identifier(tmp_path, manifest).identify("https://shop.test/api/products/1", "TRACE"), "unsupported_method")


def test_static_path_precedes_template_before_method_selection(tmp_path):
    def change(spec):
        response = copy.deepcopy(spec["paths"]["/products/{id}"]["get"]["responses"])
        spec["paths"]["/products/search"] = {"post": {"operationId": "searchProducts", "responses": response}}

    manifest = source_package(tmp_path, change=change)
    tool = identifier(tmp_path, manifest)
    url = "https://shop.test/api/products/search"
    assert_failure(tool.identify(url, "GET"), "operation_not_unique")
    result = tool.identify(url, "POST")
    assert result.decision == "identified"
    assert result.identity.operation_id == "searchProducts"
    gate = OfficialResponseGate(PlatformRegistry(tmp_path))
    assert gate.validate(gate_request(url)).errors[0].code == "operation_not_unique"
    assert gate.validate(gate_request(url, "POST")).operation_id == result.identity.operation_id


def test_overlapping_dynamic_routes_are_rejected(tmp_path):
    def operation(name, parameter):
        return {"get": {"operationId": name, "parameters": [
            {"name": parameter, "in": "path", "required": True, "schema": {"type": "string"}}],
            "responses": {"200": {"description": "test"}}}}

    def change(spec):
        spec["paths"]["/a/{id}"] = operation("getA", "id")
        spec["paths"]["/{kind}/fixed"] = operation("getFixed", "kind")

    manifest = source_package(tmp_path, change=change)
    assert_failure(identifier(tmp_path, manifest).identify("https://shop.test/api/a/fixed", "GET"), "operation_not_unique")


def test_query_preserves_duplicate_values_empty_values_and_reviewed_context(tmp_path):
    query = {"fields": ["id", "title"], "empty": [""]}
    manifest = source_package(tmp_path, contexts=[query])
    tool = identifier(tmp_path, manifest)
    url = "https://shop.test/api/products/1?fields=id&fields=title&empty="
    result = tool.identify(url, "GET")
    assert result.decision == "identified", result
    assert result.identity.query == query
    assert_failure(tool.identify("https://shop.test/api/products/1?fields=title&fields=id&empty=", "GET"), "unsupported_context")
    assert_failure(tool.identify("https://shop.test/api/products/1", "GET"), "unsupported_context")


def test_percent_encoded_path_is_not_decoded_into_another_route(tmp_path):
    manifest = source_package(tmp_path)
    request = normalized("https://shop.test/api/products/prod%2F1")
    assert request.path == "/api/products/prod/1"
    result = identifier(tmp_path, manifest).identify_request(request)
    assert result.decision == "identified", result
    assert result.request_id == request.request_id
    assert result.identity.path == "/products/{id}"
    assert result.identity.path_parameters == {"id": "prod%2F1"}


@pytest.mark.parametrize("url", ["http://[bad", "https://shop.test:bad/api/products/1",
                                  "https://user@shop.test/api/products/1", "https://@shop.test/api/products/1",
                                  "https://shop.test/api/products/1#fragment", "/api/products/1"])
def test_invalid_urls_fail_before_any_guess(tmp_path, url):
    manifest = source_package(tmp_path)
    assert_failure(identifier(tmp_path, manifest).identify(url, "GET"), "invalid_url")


def test_invalid_query_utf8_does_not_get_replaced_and_matched(tmp_path):
    manifest = source_package(tmp_path, contexts=[{"q": ["\ufffd"]}])
    result = identifier(tmp_path, manifest).identify("https://shop.test/api/products/1?q=%FF", "GET")
    assert result.decision == "unverifiable"
    assert result.errors[0].code in ("invalid_url", "unsupported_context")


def test_unreviewed_contract_and_disabled_binding_fail_closed(tmp_path):
    manifest = source_package(tmp_path, approved=False)
    assert_failure(identifier(tmp_path, manifest).identify("https://shop.test/api/products/1", "GET"), "contract_not_approved")
    assert_failure(identifier(tmp_path, manifest, enabled=False).identify("https://shop.test/api/products/1", "GET"), "binding_disabled")


@pytest.mark.parametrize("change", [{"platform_id": "other"}, {"platform_version": "2.0"},
                                     {"spec_sha256": "0" * 64}])
def test_binding_contract_identity_must_match_exactly(tmp_path, change):
    manifest = source_package(tmp_path)
    assert_failure(identifier(tmp_path, manifest, **change).identify("https://shop.test/api/products/1", "GET"),
                   "binding_contract_mismatch")


def test_duplicate_bindings_are_ambiguous_even_if_one_is_disabled(tmp_path):
    manifest = source_package(tmp_path)
    bindings = BindingConfig(bindings=[binding_for(manifest), binding_for(manifest, binding_id="other", enabled=False)])
    tool = PlatformIdentifier(PlatformRegistry(tmp_path), bindings)
    assert_failure(tool.identify("https://shop.test/api/products/1", "GET"), "binding_not_unique")


def test_multiple_contract_versions_are_not_resolved_by_binding_preference(tmp_path):
    first = source_package(tmp_path, folder="first")
    source_package(tmp_path, folder="second", platform_version="2.0")
    tool = identifier(tmp_path, first)
    assert_failure(tool.identify("https://shop.test/api/products/1", "GET"), "site_not_unique")


def test_registry_overlapping_prefixes_are_not_resolved_by_longest_prefix(tmp_path):
    manifest = source_package(tmp_path, folder="api")
    source_package(tmp_path, folder="root", base="https://shop.test")
    assert_failure(identifier(tmp_path, manifest).identify("https://shop.test/api/products/1", "GET"), "site_not_unique")


def test_trusted_runtime_context_can_select_environment_but_not_registry_version(tmp_path):
    manifest = source_package(tmp_path)
    bindings = BindingConfig(bindings=[binding_for(manifest), binding_for(
        manifest, binding_id="stage-binding", environment_id="stage-env", deployment_id="stage-deploy", site_id="stage-shop")])
    tool = PlatformIdentifier(PlatformRegistry(tmp_path), bindings)
    url = "https://shop.test/api/products/1"
    assert_failure(tool.identify(url, "GET"), "binding_not_unique")
    result = tool.identify(url, "GET", context=RuntimeContext(
        environment_id="stage-env", deployment_id="stage-deploy", service_id="store"))
    assert result.decision == "identified", result
    assert result.identity.site_id == "stage-shop"
    assert result.identity.binding_id == "stage-binding"


def test_forwarded_and_claimed_platform_headers_do_not_override_runtime_binding(tmp_path):
    manifest = source_package(tmp_path)
    request = normalized("https://shop.test/api/products/1", headers=(
        ("host", "shop.test"), ("forwarded", "host=other.test;proto=http"),
        ("x-forwarded-host", "other.test"), ("x-platform-id", "woocommerce"),
        ("x-environment-id", "other-env")))
    result = identifier(tmp_path, manifest).identify_request(request)
    assert result.decision == "identified", result
    assert result.identity.platform_id == "synthetic"
    assert result.identity.environment_id == "test-env"


def test_duplicate_host_headers_are_rejected(tmp_path):
    manifest = source_package(tmp_path)
    request = normalized("https://shop.test/api/products/1", headers=(("host", "shop.test"), ("Host", "other.test")))
    assert_failure(identifier(tmp_path, manifest).identify_request(request), "ambiguous_host")


def test_from_paths_reads_binding_config_without_mutating_files(tmp_path):
    manifest = source_package(tmp_path / "contracts")
    config = BindingConfig(bindings=[binding_for(manifest)])
    path = tmp_path / "bindings.yaml"
    raw = yaml.safe_dump(config.model_dump(mode="json")).encode("utf-8")
    path.write_bytes(raw)
    tool = PlatformIdentifier.from_paths(tmp_path / "contracts", path)
    assert tool.identify("https://shop.test/api/products/1", "GET").decision == "identified"
    assert path.read_bytes() == raw


def test_percent_encoded_internal_path_item_reference_matches_in_b_and_i(tmp_path):
    """合法 URI fragment 先解碼再解析 Pointer，不可讓 I 在已載入規格上拋 KeyError。"""
    def change(spec):
        item = copy.deepcopy(spec["paths"]["/products/{id}"])
        spec["components"] = {"pathItems": {"Product": item}}
        spec["paths"]["/products/{id}"] = {"$ref": "#/components/pathItems/%50roduct"}

    manifest = source_package(tmp_path, change=change)
    url = "https://shop.test/api/products/1"
    result = identifier(tmp_path, manifest).identify(url, "GET")
    assert result.decision == "identified", result
    assert result.identity.operation_id == "getProduct"
    checked = OfficialResponseGate(PlatformRegistry(tmp_path)).validate(gate_request(url))
    assert checked.valid, checked
    assert checked.operation_id == result.identity.operation_id


def test_path_vendor_extension_is_not_loaded_as_a_route(tmp_path):
    """paths 的 x-* 值可以是字串；它不是 Path Item，不應參與 servers 或 operation 檢查。"""
    manifest = source_package(tmp_path, change=lambda spec: spec["paths"].update({
        "x-origin-note": "Synthetic source metadata"}))
    result = identifier(tmp_path, manifest).identify("https://shop.test/api/products/1", "GET")
    assert result.decision == "identified", result
    assert result.identity.operation_id == "getProduct"


@pytest.mark.parametrize("intermediate", [False, True])
def test_path_reference_cannot_hide_server_override_in_a_sibling(tmp_path, intermediate):
    """3.0 的合法引用不能讓原始或中間 Path Item 的 servers 覆寫被丟掉後放行。"""
    def change(spec):
        spec["openapi"] = "3.0.3"
        target = copy.deepcopy(spec["paths"]["/products/{id}"])
        spec["x-path-items"] = {"Product": target}
        overridden = {"$ref": "#/x-path-items/Product", "servers": [{"url": "https://other.test"}]}
        if intermediate:
            spec["x-path-items"]["Intermediate"] = overridden
            spec["paths"]["/products/{id}"] = {"$ref": "#/x-path-items/Intermediate"}
        else:
            spec["paths"]["/products/{id}"] = overridden

    source_package(tmp_path, change=change)
    with pytest.raises(ValueError):
        PlatformRegistry(tmp_path)


@pytest.mark.parametrize("url", ["https://shop.test/api/products/one\ntwo",
                                  "https://shop.test/api/products/%ZZ",
                                  "https://shop.test:65536/api/products/1",
                                  "https://shop.test/api/products/1?q=%FF"])
def test_b_and_i_reject_the_same_malformed_url_before_selection(tmp_path, url):
    """parser 不可刪控制字元或替代無效 UTF-8，導致 B/I 指向被改寫的請求。"""
    manifest = source_package(tmp_path)
    result = identifier(tmp_path, manifest).identify(url, "GET")
    checked = OfficialResponseGate(PlatformRegistry(tmp_path)).validate(gate_request(url))
    assert_failure(result, "invalid_url")
    assert checked.decision == "unverifiable" and checked.valid is False
    assert checked.errors[0].code == "invalid_url"


def add_compound_operation(spec, template):
    """建立同一個 segment 中有兩個參數的合法合成操作。"""
    operation = copy.deepcopy(spec["paths"]["/products/{id}"]["get"])
    operation["operationId"] = "getCombined"
    operation["parameters"] = [{"name": name, "in": "path", "required": True, "schema": {"type": "string"}}
                               for name in ("first", "second")]
    spec["paths"][template] = {"get": operation}


@pytest.mark.parametrize("template,actual", [("/combined/{first}{second}", "/combined/abcd"),
                                            ("/combined/{first}-{second}", "/combined/alpha-beta-gamma")])
def test_parameter_split_ambiguity_is_not_resolved_by_regex_greediness(tmp_path, template, actual):
    """同一 template 可以有多組參數拆法時，B/I 都不可任選 greedy 的第一組。"""
    manifest = source_package(tmp_path, change=lambda spec: add_compound_operation(spec, template))
    url = "https://shop.test/api" + actual
    result = identifier(tmp_path, manifest).identify(url, "GET")
    checked = OfficialResponseGate(PlatformRegistry(tmp_path)).validate(gate_request(url))
    assert_failure(result, "operation_not_unique")
    assert checked.valid is False and checked.decision == "unverifiable"
    assert checked.errors[0].code == "operation_not_unique"


def test_compound_segment_with_one_parameter_split_remains_supported(tmp_path):
    """明確分隔點只有一個時，兩個參數仍能取得唯一值。"""
    manifest = source_package(tmp_path, change=lambda spec: add_compound_operation(spec, "/combined/{first}-{second}"))
    url = "https://shop.test/api/combined/alpha-beta"
    result = identifier(tmp_path, manifest).identify(url, "GET")
    assert result.decision == "identified", result
    assert result.identity.path_parameters == {"first": "alpha", "second": "beta"}
    checked = OfficialResponseGate(PlatformRegistry(tmp_path)).validate(gate_request(url))
    assert checked.valid is True, checked
    assert checked.operation_id == result.identity.operation_id == "getCombined"


def test_exact_path_precedes_a_template_with_ambiguous_parameter_splits(tmp_path):
    """靜態 exact path 本來有唯一操作，其他動態路由的拆分歧義不應阻擋它。"""
    def change(spec):
        add_compound_operation(spec, "/combined/{first}{second}")
        responses = copy.deepcopy(spec["paths"]["/products/{id}"]["get"]["responses"])
        spec["paths"]["/combined/abcd"] = {"get": {"operationId": "getExact", "responses": responses}}

    manifest = source_package(tmp_path, change=change)
    url = "https://shop.test/api/combined/abcd"
    result = identifier(tmp_path, manifest).identify(url, "GET")
    assert result.decision == "identified", result
    assert result.identity.operation_id == "getExact"
    assert result.identity.path_parameters == {}
    checked = OfficialResponseGate(PlatformRegistry(tmp_path)).validate(gate_request(url))
    assert checked.valid is True, checked
    assert checked.operation_id == "getExact"


def test_exact_path_precedes_a_template_with_duplicate_parameter_names(tmp_path):
    """未選定動態路由中的重複參數名，不能阻擋已明確匹配的靜態操作。"""
    def change(spec):
        dynamic = copy.deepcopy(spec["paths"]["/products/{id}"])
        dynamic["get"]["operationId"] = "getRepeated"
        spec["paths"]["/{id}/{id}"] = dynamic
        responses = copy.deepcopy(spec["paths"]["/products/{id}"]["get"]["responses"])
        spec["paths"]["/products/exact"] = {"get": {"operationId": "getExact", "responses": responses}}

    manifest = source_package(tmp_path, change=change)
    url = "https://shop.test/api/products/exact"
    result = identifier(tmp_path, manifest).identify(url, "GET")
    assert result.decision == "identified", result
    assert result.identity.operation_id == "getExact"
    checked = OfficialResponseGate(PlatformRegistry(tmp_path)).validate(gate_request(url))
    assert checked.valid is True, checked
