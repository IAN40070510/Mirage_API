"""Pinned Medusa v2.22.4 Store/Auth subset regression checks.

This verifies repository fixture integrity. It does not certify any live deployment.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
GATE_SPEC = ROOT / "inputs/platforms/medusa/openapi.yaml"
PROFILE_SPEC = ROOT / "inputs/sources/medusa/openapi.yaml"
SOURCE_CONFIG = ROOT / "inputs/sources/medusa/source.yaml"
MANIFEST_EXAMPLE = ROOT / "inputs/platforms/medusa/manifest.yaml.example"
PINNED_COMMIT = "81edb06c323812773c9c0dcc4da2d9784f3b3319"
PINNED_SUBSET_SHA256 = "15c794cf596866f13bf96b715db66470011406f659e2eadbf4761dfdbb2ccc96"
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


@pytest.fixture(scope="module")
def medusa_spec():
    return yaml.safe_load(GATE_SPEC.read_bytes())


def test_profile_and_validator_use_exactly_same_pinned_bytes():
    gate = GATE_SPEC.read_bytes()
    source = PROFILE_SPEC.read_bytes()
    assert gate == source, "D and I must not use different contract bytes"
    assert hashlib.sha256(gate).hexdigest() == PINNED_SUBSET_SHA256

    cfg = yaml.safe_load(SOURCE_CONFIG.read_text(encoding="utf-8"))
    manifest = yaml.safe_load(MANIFEST_EXAMPLE.read_text(encoding="utf-8"))
    assert cfg["spec_sha256"] == manifest["spec_sha256"] == PINNED_SUBSET_SHA256
    assert cfg["source_revision"] == manifest["source_revision"] == PINNED_COMMIT
    assert cfg["platform_version"] == str(manifest["platform_version"]) == "2.22.4"
    assert cfg["approved"] is False and manifest["approved"] is False


def test_pinned_subset_coverage_and_official_document_version(medusa_spec):
    assert medusa_spec["openapi"] == "3.0.0"
    # The official v2.22.4 tag's Store API Reference still declares 2.22.3.
    assert str(medusa_spec["info"]["version"]) == "2.22.3"
    paths = medusa_spec["paths"]
    assert len(paths) == 67
    assert sum(k in HTTP_METHODS for p in paths.values() for k in p) == 77
    assert len(medusa_spec["components"]["schemas"]) == 133


def test_store_operation_field_whitelists_and_refund_schema(medusa_spec):
    operations = [
        operation
        for path in medusa_spec["paths"].values()
        for method, operation in path.items()
        if method in HTTP_METHODS
    ]
    allowed = [operation["x-allowed"] for operation in operations if "x-allowed" in operation]
    assert len(allowed) == 51
    assert all(isinstance(names, list) and len(names) > 0 for names in allowed)
    assert all(all(isinstance(name, str) for name in names) for names in allowed)
    for url in ("/store/products", "/store/products/{id}"):
        op = medusa_spec["paths"][url]["get"]
        assert "id" in op["x-allowed"]
        assert "title" in op["x-allowed"]
    refund = medusa_spec["components"]["schemas"]["BaseRefund"]
    assert refund["properties"]["idempotency_key"]["type"] == "string"


def test_all_internal_refs_resolve_without_network(medusa_spec):
    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "$ref":
                    assert isinstance(item, str) and item.startswith("#/"), item
                    node = medusa_spec
                    for segment in item[2:].split("/"):
                        node = node[segment.replace("~1", "/").replace("~0", "~")]
                else:
                    walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(medusa_spec)
