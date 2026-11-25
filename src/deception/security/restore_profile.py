"""D-74 部署模式啟動契約：單機無外部依賴，外部 Fence 嚴格拒絕隱式降級。"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
from typing import Mapping


_FENCE_FIELDS = (
    "MIRAGE_FENCE_AUTHORITY_DSN",
    "MIRAGE_FENCE_NAMESPACE",
    "MIRAGE_FENCE_EPOCH",
    "MIRAGE_FENCE_PUBLISHER_PUBLIC_KEY_FILE",
    "MIRAGE_FENCE_HEAD_PUBLIC_KEY_FILE",
)
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


class RestoreProfileConfigurationError(ValueError):
    """表示部署安全模式無法被明確驗證；錯誤不得包含連線密碼或金鑰。"""


@dataclass(frozen=True)
class RestoreDeploymentProfile:
    """不可變的已解析部署宣告；不把本機模式宣稱為整機抗回滾保證。"""

    name: str
    contract_version: int
    whole_host_rollback_guarantee: bool
    fence_namespace: str | None = None
    fence_epoch: str | None = None
    publisher_key_digest: str | None = None
    head_key_digest: str | None = None

    def __post_init__(self) -> None:
        """阻止呼叫者手動建構矛盾的 Profile 或偽造整機保證旗標。"""
        if (type(self.contract_version) is not int or self.contract_version != 1
                or self.name not in {"standard_single_node", "external_fence"}
                or type(self.whole_host_rollback_guarantee) is not bool
                or self.whole_host_rollback_guarantee):
            raise RestoreProfileConfigurationError("restore_profile_contract_invalid")
        fence_values = (self.fence_namespace, self.fence_epoch,
                        self.publisher_key_digest, self.head_key_digest)
        if self.name == "standard_single_node" and any(value is not None for value in fence_values):
            raise RestoreProfileConfigurationError("restore_profile_standard_has_fence_state")
        if self.name == "external_fence" and (
                any(not isinstance(value, str) or not value for value in fence_values)
                or not all(re.fullmatch(r"[0-9a-f]{64}", value) for value in fence_values[2:])
                or not all(_IDENTIFIER.fullmatch(value) for value in fence_values[:2])
                or self.publisher_key_digest == self.head_key_digest):
            raise RestoreProfileConfigurationError("restore_profile_external_pin_invalid")


def _public_key_digest(path: str) -> str:
    """讀取明確檔案中的 32-byte Ed25519 公鑰（64 位 hex），錯誤不回傳路徑。"""
    try:
        if not path or not Path(path).is_file():
            raise ValueError("missing key")
        encoded = Path(path).read_text(encoding="ascii").strip()
        if re.fullmatch(r"[0-9a-f]{64}", encoded) is None:
            raise ValueError("invalid key encoding")
        return hashlib.sha256(bytes.fromhex(encoded)).hexdigest()
    except (OSError, UnicodeError, ValueError):
        raise RestoreProfileConfigurationError("restore_profile_public_key_unverifiable") from None


def load_restore_profile(environment: Mapping[str, str] | None = None) -> RestoreDeploymentProfile:
    """讀取明確版本、模式及 Fence Pin；標準模式不需要外部服務或密鑰。

    本步僅驗證**部署宣告**，不代表外部最新 Head 可用、外部域隔離或
    BD-05 Restore Quarantine 已驗收。正式 Sender 仍需自己的獨立 Release Gate。
    """
    env = os.environ if environment is None else environment
    name = env.get("MIRAGE_RESTORE_PROFILE")
    if env.get("MIRAGE_RESTORE_PROFILE_VERSION") != "1":
        raise RestoreProfileConfigurationError("restore_profile_version_required")
    if name == "standard_single_node":
        if any(key.startswith("MIRAGE_FENCE_") for key in env):
            raise RestoreProfileConfigurationError("restore_profile_fence_downgrade_refused")
        return RestoreDeploymentProfile(name=name, contract_version=1,
                                        whole_host_rollback_guarantee=False)
    if name != "external_fence":
        raise RestoreProfileConfigurationError("restore_profile_explicit_selection_required")
    if any(not env.get(key) for key in _FENCE_FIELDS):
        raise RestoreProfileConfigurationError("restore_profile_fence_configuration_incomplete")
    namespace, epoch = env["MIRAGE_FENCE_NAMESPACE"], env["MIRAGE_FENCE_EPOCH"]
    if not _IDENTIFIER.fullmatch(namespace) or not _IDENTIFIER.fullmatch(epoch):
        raise RestoreProfileConfigurationError("restore_profile_fence_scope_invalid")
    # DSN 唯一用途是後續外部連線，不存入 Profile，也不出現在 repr／例外。
    if not env["MIRAGE_FENCE_AUTHORITY_DSN"].startswith(("postgresql://", "postgres://")):
        raise RestoreProfileConfigurationError("restore_profile_fence_dsn_invalid")
    return RestoreDeploymentProfile(
        name=name, contract_version=1, whole_host_rollback_guarantee=False,
        fence_namespace=namespace, fence_epoch=epoch,
        publisher_key_digest=_public_key_digest(env["MIRAGE_FENCE_PUBLISHER_PUBLIC_KEY_FILE"]),
        head_key_digest=_public_key_digest(env["MIRAGE_FENCE_HEAD_PUBLIC_KEY_FILE"]),
    )
