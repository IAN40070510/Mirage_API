"""B：從明確部署綁定識別平台／版本／操作，供 C 與 D 使用。"""

from .identifier import PlatformIdentifier
from .models import (BindingConfig, DeploymentBinding, IdentificationResult,
                     IdentifiedOperation, RuntimeContext)

__all__ = ["PlatformIdentifier", "BindingConfig", "DeploymentBinding", "IdentificationResult",
           "IdentifiedOperation", "RuntimeContext"]
