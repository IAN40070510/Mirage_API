"""D 階段的合成規格測試；不代表任何電商平台的官方相容性。"""

import hashlib

import pytest
import yaml

from deception.profile_builder import ProfileError, ProfileTool, build_profile


def source_package(root, *, version="3.1.0", approved=False, spec_change=None, source_change=None):
    """建立可追溯的本機來源，讓測試不需下載遠端規格。"""
    root.mkdir(parents=True, exist_ok=True)
    spec = {
        "openapi": version,
        "info": {"title": "Synthetic profile test", "version": "1.2.3"},
        "security": [{"ApiKey": []}],
        "paths": {
            "/products/{id}": {
                "parameters": [
                    {"in": "path", "name": "id", "required": True, "schema": {"type": "string"}},
                    {"in": "query", "name": "limit", "schema": {"type": "integer", "default": 1}},
                ],
                "get": {
                    "operationId": "getProduct",
                    "parameters": [
                        {"in": "query", "name": "limit", "schema": {"type": "integer", "default": 2}},
                    ],
                    "responses": {
                        "200": {
                            "description": "Product",
                            "headers": {"X-Total": {"schema": {"type": "integer"}}},
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Product"}}},
                        },
                        "204": {"description": "No content"},
                        "2XX": {"description": "Other success"},
                        "default": {"description": "Unspecified status"},
                    },
                },
                "post": {
                    "operationId": "updateProduct",
                    "security": [],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Product"}}},
                    },
                    "responses": {"204": {"description": "Updated"}},
                },
            },
        },
        "components": {
            "securitySchemes": {"ApiKey": {"type": "apiKey", "in": "header", "name": "X-Api-Key"}},
            "schemas": {
                "Product": {
                    "type": "object",
                    "required": ["id"],
                    "properties": {
                        "id": {"type": "string"},
                        "related": {"type": "array", "items": {"$ref": "#/components/schemas/Product"}},
                    },
                },
            },
        },
    }
    if spec_change:
        spec_change(spec)
    data = yaml.safe_dump(spec, sort_keys=False).encode("utf-8")
    (root / "openapi.yaml").write_bytes(data)
    source = {
        "schema_version": 1,
        "platform_id": "synthetic",
        "platform_version": "1.2.3",
        "source_url": "https://example.org/test-only/openapi.yaml",
        "source_revision": "test-only-fixed-revision",
        "spec_sha256": hashlib.sha256(data).hexdigest(),
        "approved": approved,
        "openapi_file": "openapi.yaml",
    }
    if source_change:
        source.update(source_change)
    path = root / "source.yaml"
    path.write_text(yaml.safe_dump(source), encoding="utf-8")
    return path, data, spec


def operation_context(output, profile, **changes):
    options = {
        "platform_id": "synthetic",
        "platform_version": "1.2.3",
        "spec_sha256": profile.source.spec_sha256,
        "method": "GET",
        "path": "/products/{id}",
        "allow_unreviewed": True,
    }
    options.update(changes)
    return ProfileTool(output).get_operation(**options)


@pytest.mark.parametrize("version", ["3.0.3", "3.1.0"])
def test_build_preserves_contract_and_source_bytes(tmp_path, version):
    source, data, spec = source_package(tmp_path / "source", version=version)
    output = tmp_path / "generated"
    profile = build_profile(source, output)
    assert profile.openapi_version == version
    assert profile.spec_info_version == "1.2.3"
    assert profile.source.approved is False
    assert profile.source.spec_sha256 == hashlib.sha256(data).hexdigest()
    assert len(profile.operations) == 2
    assert (output / "profiles/synthetic.yaml").is_file()
    assert (output / "schemas/synthetic" / f"{profile.source.spec_sha256}.yaml").read_bytes() == data

    context = operation_context(output, profile)
    operation = context.operation
    assert operation.operation_id == "getProduct"
    assert operation.method == "GET"
    assert operation.path == "/products/{id}"
    assert "~1products~1{id}" in operation.schema_pointer
    assert operation.schema_pointer.endswith("/get")
    assert operation.responses == spec["paths"]["/products/{id}"]["get"]["responses"]
    assert operation.request_body is None
    assert context.specification == spec
    assert context.source == profile.source


def test_parameter_override_and_security_inheritance(tmp_path):
    source, _, spec = source_package(tmp_path / "source")
    output = tmp_path / "generated"
    profile = build_profile(source, output)
    context = operation_context(output, profile)
    parameters = {(p["in"], p["name"]): p for p in context.operation.parameters}
    assert len(parameters) == len(context.operation.parameters) == 2
    assert parameters[("path", "id")]["required"] is True
    assert parameters[("query", "limit")]["schema"]["default"] == 2
    assert context.operation.security == [{"ApiKey": []}]

    post = operation_context(output, profile, method="POST").operation
    assert post.security == []
    assert post.request_body == spec["paths"]["/products/{id}"]["post"]["requestBody"]


def test_boolean_and_recursive_schemas_are_preserved(tmp_path):
    def change(spec):
        spec["components"]["schemas"]["Product"]["properties"].update({"allowed": True, "forbidden": False})

    source, _, spec = source_package(tmp_path / "source", spec_change=change)
    output = tmp_path / "generated"
    profile = build_profile(source, output)
    context = operation_context(output, profile)
    assert context.specification["components"]["schemas"] == spec["components"]["schemas"]
    assert context.operation.responses["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/Product"
    }


def test_unreviewed_profile_requires_explicit_preview(tmp_path):
    source, _, _ = source_package(tmp_path / "source")
    output = tmp_path / "generated"
    profile = build_profile(source, output)
    with pytest.raises(ProfileError):
        operation_context(output, profile, allow_unreviewed=False)
    assert operation_context(output, profile).source.approved is False


def test_explicitly_reviewed_source_can_be_queried(tmp_path):
    source, _, _ = source_package(tmp_path / "source", approved=True)
    output = tmp_path / "generated"
    profile = build_profile(source, output)
    assert operation_context(output, profile, allow_unreviewed=False).source.approved is True


@pytest.mark.parametrize("changes", [
    {"platform_version": "other-version"},
    {"spec_sha256": "0" * 64},
    {"method": "DELETE"},
    {"path": "/products/actual-id"},
])
def test_lookup_requires_exact_identity_and_operation(tmp_path, changes):
    source, _, _ = source_package(tmp_path / "source")
    output = tmp_path / "generated"
    profile = build_profile(source, output)
    with pytest.raises(ProfileError):
        operation_context(output, profile, **changes)


def test_hash_mismatch_is_rejected_before_output(tmp_path):
    source, _, _ = source_package(tmp_path / "source", source_change={"spec_sha256": "0" * 64})
    output = tmp_path / "generated"
    with pytest.raises(ProfileError):
        build_profile(source, output)
    assert not (output / "profiles/synthetic.yaml").exists()


@pytest.mark.parametrize("reference", ["https://example.org/schema.json", "#/components/schemas/Missing"])
def test_external_and_unresolved_references_are_rejected(tmp_path, reference):
    def change(spec):
        spec["paths"]["/products/{id}"]["get"]["responses"]["200"]["content"]["application/json"]["schema"] = {
            "$ref": reference
        }

    source, _, _ = source_package(tmp_path / "source", spec_change=change)
    with pytest.raises(ProfileError):
        build_profile(source, tmp_path / "generated")


def test_source_file_cannot_escape_source_directory(tmp_path):
    source, data, _ = source_package(tmp_path / "source", source_change={"openapi_file": "../outside.yaml"})
    (tmp_path / "outside.yaml").write_bytes(data)
    with pytest.raises(ProfileError):
        build_profile(source, tmp_path / "generated")


@pytest.mark.parametrize("artifact", ["profile", "specification"])
def test_corrupted_generated_artifacts_are_rejected(tmp_path, artifact):
    source, _, _ = source_package(tmp_path / "source")
    output = tmp_path / "generated"
    profile = build_profile(source, output)
    if artifact == "profile":
        (output / "profiles/synthetic.yaml").write_text("operations: invalid\n", encoding="utf-8")
    else:
        snapshot = output / "schemas/synthetic" / f"{profile.source.spec_sha256}.yaml"
        snapshot.write_bytes(snapshot.read_bytes() + b"\n# modified\n")
    with pytest.raises(ProfileError):
        operation_context(output, profile)


def test_rebuilding_same_identity_is_deterministic(tmp_path):
    source, _, _ = source_package(tmp_path / "source")
    output = tmp_path / "generated"
    first = build_profile(source, output)
    encoded = (output / "profiles/synthetic.yaml").read_bytes()
    second = build_profile(source, output)
    assert second == first
    assert (output / "profiles/synthetic.yaml").read_bytes() == encoded


@pytest.mark.parametrize("change", ["version", "specification"])
def test_different_identity_cannot_silently_replace_profile(tmp_path, change):
    source, _, _ = source_package(tmp_path / "source")
    output = tmp_path / "generated"
    build_profile(source, output)
    encoded = (output / "profiles/synthetic.yaml").read_bytes()
    if change == "version":
        source, _, _ = source_package(tmp_path / "source", source_change={"platform_version": "2.0.0"})
    else:
        source, _, _ = source_package(tmp_path / "source", spec_change=lambda spec: spec["info"].update(title="Changed"))
    with pytest.raises(ProfileError):
        build_profile(source, output)
    assert (output / "profiles/synthetic.yaml").read_bytes() == encoded


@pytest.mark.parametrize("version", ["3.0.3", "3.1.0"])
def test_reference_objects_resolve_without_expanding_schemas(tmp_path, version):
    def change(spec):
        components = spec["components"]
        item = spec["paths"]["/products/{id}"]
        components["parameters"] = {"ProductId": item["parameters"][0]}
        item["parameters"][0] = {"$ref": "#/components/parameters/ProductId"}
        response = item["get"]["responses"]["200"]
        components["headers"] = {"Total": response["headers"]["X-Total"]}
        response["headers"]["X-Total"] = {"$ref": "#/components/headers/Total"}
        components["responses"] = {"ProductResponse": response}
        item["get"]["responses"]["200"] = {"$ref": "#/components/responses/ProductResponse"}
        components["requestBodies"] = {"ProductBody": item["post"]["requestBody"]}
        item["post"]["requestBody"] = {"$ref": "#/components/requestBodies/ProductBody"}

    source, _, _ = source_package(tmp_path / "source", version=version, spec_change=change)
    output = tmp_path / "generated"
    profile = build_profile(source, output)
    operation = operation_context(output, profile).operation
    assert operation.parameters[0] == {
        "in": "path", "name": "id", "required": True, "schema": {"type": "string"}
    }
    response = operation.responses["200"]
    assert response["headers"]["X-Total"] == {"schema": {"type": "integer"}}
    assert response["content"]["application/json"]["schema"] == {"$ref": "#/components/schemas/Product"}
    post = operation_context(output, profile, method="POST").operation
    assert post.request_body["required"] is True
    assert post.request_body["content"]["application/json"]["schema"] == {"$ref": "#/components/schemas/Product"}


def test_false_schema_is_a_present_contract(tmp_path):
    def change(spec):
        spec["paths"]["/products/{id}"]["get"]["responses"]["200"]["content"]["application/json"]["schema"] = False

    source, _, _ = source_package(tmp_path / "source", spec_change=change)
    output = tmp_path / "generated"
    profile = build_profile(source, output)
    assert "getProduct/200/application/json:schema_missing" not in profile.warnings
    operation = operation_context(output, profile).operation
    assert operation.responses["200"]["content"]["application/json"]["schema"] is False


@pytest.mark.parametrize("artifact", ["source", "specification"])
def test_duplicate_yaml_keys_cannot_replace_source_or_contract(tmp_path, artifact):
    source, data, _ = source_package(tmp_path / "source")
    if artifact == "source":
        source.write_bytes(source.read_bytes() + b"\napproved: true\n")
    else:
        # 更新正確雜湊，確保拒絕的是重複 key，而不是先撞上 hash mismatch。
        data += b"\ninfo:\n  title: Replaced\n  version: '1.2.3'\n"
        (source.parent / "openapi.yaml").write_bytes(data)
        descriptor = yaml.safe_load(source.read_bytes())
        descriptor["spec_sha256"] = hashlib.sha256(data).hexdigest()
        source.write_text(yaml.safe_dump(descriptor), encoding="utf-8")
    with pytest.raises(ProfileError):
        build_profile(source, tmp_path / "generated")


def test_validly_typed_but_modified_operation_is_rejected(tmp_path):
    source, _, _ = source_package(tmp_path / "source")
    output = tmp_path / "generated"
    profile = build_profile(source, output)
    path = output / "profiles/synthetic.yaml"
    modified = yaml.safe_load(path.read_bytes())
    modified["operations"][0]["responses"]["200"]["content"]["application/json"]["schema"] = {"type": "object"}
    path.write_text(yaml.safe_dump(modified), encoding="utf-8")
    with pytest.raises(ProfileError):
        operation_context(output, profile)


def test_path_item_reference_points_to_existing_operation(tmp_path):
    def change(spec):
        item = spec["paths"].pop("/products/{id}")
        spec["components"]["pathItems"] = {"ProductPath": item}
        spec["paths"]["/products/{id}"] = {"$ref": "#/components/pathItems/ProductPath"}
        spec["paths"]["x-maintainer-note"] = {"description": "A paths extension, not an API operation"}

    source, _, _ = source_package(tmp_path / "source", spec_change=change)
    output = tmp_path / "generated"
    profile = build_profile(source, output)
    context = operation_context(output, profile)
    assert len(profile.operations) == 2
    node = context.specification
    for token in context.operation.schema_pointer[2:].split("/"):
        node = node[token.replace("~1", "/").replace("~0", "~")]
    assert node["operationId"] == "getProduct"
    assert node["responses"]["200"] == context.operation.responses["200"]
