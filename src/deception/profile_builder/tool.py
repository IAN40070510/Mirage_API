"""供協調器查詢 D Profile，不負責 B 的網站識別或 I 的回應放行。"""

import re
from pathlib import Path

from .builder import ProfileError, extract_profile, local_path, read_yaml
from .models import OperationContext, PlatformProfile


class ProfileTool:
    """以明確平台、版本、雜湊與 operation 定位，避免跨來源自動回退。"""

    def __init__(self, output_root: Path):
        self.output_root = output_root

    def get_operation(self, *, platform_id: str, platform_version: str, spec_sha256: str,
                      method: str, path: str, allow_unreviewed: bool = False) -> OperationContext:
        """回傳操作與契約快照；未審來源只能透過顯式參數做離線預覽。"""
        try:
            # 在拿 platform_id 組路徑前限制名稱，避免工具呼叫者指定任意檔案。
            if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", platform_id):
                raise ProfileError("Invalid platform_id")
            profile = PlatformProfile.model_validate(read_yaml(
                local_path(self.output_root, f"profiles/{platform_id}.yaml").read_bytes()))
            source = profile.source
            if (source.platform_id, source.platform_version, source.spec_sha256) != (
                platform_id, platform_version, spec_sha256
            ):
                raise ProfileError("Profile identity does not match platform/version/hash")
            if not source.approved and not allow_unreviewed:
                raise ProfileError("Profile source is not approved")
            data = local_path(self.output_root, profile.schema_file).read_bytes()
            # 重算摘要與 Profile，拒絕快照或操作摘要遭改動的產物。
            if extract_profile(source, data) != profile:
                raise ProfileError("Generated profile does not match its contract snapshot")
            matches = [operation for operation in profile.operations
                       if (operation.method, operation.path) == (method, path)]
            if len(matches) != 1:
                raise ProfileError("Operation must match one exact method and path template")
            return OperationContext(source=source, operation=matches[0], specification=read_yaml(data))
        except ProfileError:
            raise
        except Exception as exc:
            raise ProfileError(f"Cannot query profile: {exc}") from exc
