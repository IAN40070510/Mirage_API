"""Legacy Gateway bootstrap import path.

MSDSS owns the implementation. This package is not used by Mirage runtime;
the shim requires the separately installed, pinned MSDSS integration.
"""
from msdss.gateway_integration.gateway_bootstrap import (
    GatewayIntegrationSettings,
    configure_from_environment,
    configure_gateway_state,
)

__all__ = [
    "GatewayIntegrationSettings",
    "configure_from_environment",
    "configure_gateway_state",
]
