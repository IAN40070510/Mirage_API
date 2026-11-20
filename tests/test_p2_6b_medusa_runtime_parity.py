"""P2-6B: pin *known* gaps between real Store API projection and Mirage.

The anonymous baseline records top-level keys from real Medusa 2.22.4 and
is checked by a separate Docker-backed CI against the live disposable Store.
This is a regression/gap inventory, NOT a compatibility approval.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from deception.common import DatasetScope
from deception.domains.ecommerce.medusa_product import (
    MEDUSA_STORE_SHA256,
    MEDUSA_VERSION,
    SYNTHETIC_TIMESTAMP,
    _product_view,
)
from deception.domains.ecommerce.synthetic import SyntheticConfig, generate_dataset

MIRAGE_ROOT = Path(__file__).resolve().parents[1]
BASELINE = json.loads(
    (MIRAGE_ROOT / "tests/fixtures/medusa_live_store_product_20261111.json").read_text(
        encoding="utf-8"
    )
)


def _synthetic_view() -> dict:
    """Generate one isolated deterministic E view for contract gap checks."""
    scope = DatasetScope(
        site_id="p2-review",
        platform_id="medusa",
        platform_version=MEDUSA_VERSION,
        spec_sha256=MEDUSA_STORE_SHA256,
        scenario_id="product-lookup",
        run_id="p2-6b-parity",
    )
    config = SyntheticConfig(
        scope=scope, seed=20261111, product_count=1, variants_per_product=2,
        synthetic_created_at="2026-11-11T00:00:00Z",
    )
    dataset = generate_dataset(config)
    product = dataset.products[0]
    variants = [item for item in dataset.variants if item.product_id == product.id]
    return _product_view(
        product, variants, lifecycle_at=dataset.config.synthetic_created_at,
    )


def test_real_default_product_field_gap_is_explicit() -> None:
    """Match default top-level keys; keep nested E and vendor spec gaps explicit."""
    view = _synthetic_view()
    live = set(BASELINE["default_product_keys"])
    synthetic = set(view)

    # Top-level Store projection now matches the observed public key set,
    # but nested objects and variant cardinalities still differ from seed.
    assert live == synthetic
    assert "status" not in view
    assert "deleted_at" not in view and "external_id" not in view
    assert view["created_at"] != SYNTHETIC_TIMESTAMP
    assert view["collection_id"] is None
    assert isinstance(view["images"], list)
    assert isinstance(view["options"], list)
    assert len(view["options"]) == 1
    assert isinstance(view["variants"], list)
    assert all(v["deleted_at"] is None for v in view["variants"])
    assert all(v["options"][0]["option_id"] == view["options"][0]["id"]
               for v in view["variants"])
    assert all(v["created_at"] == view["created_at"] for v in view["variants"])
    assert view["created_at"] == view["updated_at"]
    assert all(v["options"][0]["value"] == v["title"] for v in view["variants"])
    assert view["images"] == []


def test_real_query_status_does_not_authorize_mirage_query_routes() -> None:
    """The live Store may support +status while this deception policy remains off."""
    assert BASELINE["status_query"] == "fields=%2Bstatus"
    assert BASELINE["status_query_expected_value"] == "published"
    policy = yaml.safe_load(
        (
            MIRAGE_ROOT
            / "domains/ecommerce/inputs/policies/medusa-product-lookup.p2-6a.yaml"
        ).read_text(encoding="utf-8")
    )
    source = yaml.safe_load(
        (
            MIRAGE_ROOT / "domains/ecommerce/inputs/sources/medusa/source.yaml"
        ).read_text(encoding="utf-8")
    )
    assert policy["enabled"] is False
    assert policy["rules"][0]["enabled"] is False
    assert policy["rules"][0]["query_contexts"] == [{}]
    assert source["approved"] is False


def test_real_missing_message_baseline_requires_requested_id() -> None:
    """404 errors must not accidentally use a fixed generic synthetic string."""
    requested = "prod_00000000000000000000000000"
    template = BASELINE["missing_error_message_template"]
    assert BASELINE["missing_error_type"] == "not_found"
    assert template.format(id=requested) == (
        "Product with id: prod_00000000000000000000000000 was not found"
    )
