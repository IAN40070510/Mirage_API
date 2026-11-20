"""P2-6B: truth-preserving Medusa 2.22.4 synthetic Store product view.

Never mistake pinned vendor OpenAPI 2.22.3 (which mandates non-null deleted_at
and default status) for the observed runtime 2.22.4 public contract.
A fully truthful view may therefore be rejected by H/I until the versioned
contract has been reviewed and repinned. Do not insert fake dates to pass I.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from deception.core.models import CompositionPlan

from .synthetic.generator import checked_dataset
from .synthetic.models import SyntheticDataset

MEDUSA_VERSION = "2.22.4"
MEDUSA_STORE_SHA256 = "ced300a2de92b9829e6e600964588e894b760f07f8d79c1df657e1abe0529058"
MEDUSA_PRODUCT_PATH = "/store/products/{id}"
# Historical placeholder remains for regression assertions only. Never emit
# this value as a lifecycle event in a Store product response.
SYNTHETIC_TIMESTAMP = "2026-01-01T00:00:00Z"


def _lifecycle_time(created: str | None) -> str:
    """Require a verified E-configured, timezone-aware logical creation event."""
    if created is None:
        raise ValueError("Medusa 200 requires an explicit synthetic creation event")
    try:
        parsed = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("Invalid synthetic creation event") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Synthetic creation event must be timezone-aware")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _synthetic_id(prefix: str, source: str) -> str:
    """Derive stable, disconnected synthetic child identities from E entities."""
    return prefix + hashlib.sha256(source.encode("utf-8")).hexdigest()[:26]


def _product_view(product, variants, *, lifecycle_at: str | None = None) -> dict:
    """Project E's actual synthetic facts and coherent option references.

    Image assets, product categories and inventory-independent optional values
    are never fabricated. No live Medusa asset, database or customer is read.
    """
    when = _lifecycle_time(lifecycle_at)
    option_id = _synthetic_id("opt_syn_", product.id + ":variant")
    option_core = {
        "id": option_id, "title": "Variant", "is_exclusive": False,
        "metadata": None, "created_at": when, "updated_at": when, "deleted_at": None,
    }
    values = []
    mapped_variants = []
    for rank, variant in enumerate(variants):
        value = {
            "id": _synthetic_id("optval_syn_", variant.id),
            "value": variant.title, "option_id": option_id, "metadata": None,
            "rank": rank, "created_at": when, "updated_at": when,
            "deleted_at": None,
        }
        values.append(value)
        mapped_variants.append({
            "id": variant.id, "product_id": product.id,
            "title": variant.title, "sku": variant.sku,
            "options": [{**value, "option": dict(option_core)}],
            "thumbnail": None,
            "width": None, "weight": None, "length": None, "height": None,
            "origin_country": None, "hs_code": None, "mid_code": None,
            "material": None, "barcode": None, "ean": None, "upc": None,
            "metadata": None, "deleted_at": None,
            "created_at": when, "updated_at": when,
            "variant_rank": rank,
            "manage_inventory": True, "allow_backorder": False,
        })
    return {
        "id": product.id, "title": product.title, "handle": product.handle,
        "description": "Synthetic catalog fixture; not a live Medusa product.",
        # Real default Store API does not include product.status/external_id/deleted_at.
        "subtitle": None, "thumbnail": None,
        "is_giftcard": False, "discountable": True,
        "width": None, "weight": None, "length": None, "height": None,
        "origin_country": None, "hs_code": None, "mid_code": None,
        "material": None, "collection_id": None, "type_id": None,
        "collection": None, "type": None,
        "categories": [], "tags": [],
        "created_at": when, "updated_at": when,
        "options": [{**option_core, "values": values}],
        # No image E facts exist. Empty is truthful; do not invent URLs.
        "images": [], "variants": mapped_variants,
    }


def adapt_medusa_product_plan(
    selected_plan: CompositionPlan, dataset: SyntheticDataset, *, product_id: str
) -> CompositionPlan:
    """Select the pinned E/F response, then leave H/I/M to reject schema drift."""
    plan = CompositionPlan.model_validate(selected_plan.model_dump(mode="json"))
    scope = plan.scope
    if (
        scope.platform_id != "medusa"
        or scope.platform_version != MEDUSA_VERSION
        or scope.spec_sha256 != MEDUSA_STORE_SHA256
        or scope.scenario_id != "product-lookup"
        or plan.method != "GET"
        or plan.path != MEDUSA_PRODUCT_PATH
        or plan.status_code not in (200, 404)
        or plan.media_type != "application/json"
    ):
        raise ValueError("unsupported Medusa product operation or contract")
    data = checked_dataset(dataset, dataset.config)
    if data.config.scope != scope:
        raise ValueError("untrusted synthetic dataset scope")
    if not product_id or not isinstance(product_id, str):
        raise ValueError("invalid selected product identity")
    products = [item for item in data.products if item.id == product_id]
    if (plan.status_code == 200) != bool(products):
        raise ValueError("scenario status disagrees with synthetic data facts")
    if products:
        product = products[0]
        variants = [item for item in data.variants if item.product_id == product.id]
        body = {"product": _product_view(
            product, variants, lifecycle_at=data.config.synthetic_created_at,
        )}
    else:
        body = {
            "type": "not_found",
            "message": f"Product with id: {product_id} was not found",
        }
    # False-date/nullable mismatches remain visible to H/I, never papered over.
    return CompositionPlan.model_validate({
        **plan.model_dump(mode="json"), "body": body, "bindings": [], "headers": {},
    })
