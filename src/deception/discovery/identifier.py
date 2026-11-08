"""B：部署綁定、已載契約與唯一操作的嚴格識別，不連線猜測真實服務。"""

from pathlib import Path

from deception.api.ingress import NormalizedRequest
from deception.profile_builder.builder import read_yaml
from mirage_validator.gate import PlatformRegistry
from mirage_validator.request_matching import (SelectionError, base_identity, match_base_url,
                                               parse_query, parse_request_url, select_operation, select_site)

from .models import (BindingConfig, IdentificationIssue, IdentificationResult,
                     IdentifiedOperation, RuntimeContext)

METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def _failure(code: str, reason: str, request_id: str | None = None) -> IdentificationResult:
    """建立無法確認身份的結果，保留追蹤 ID 與固定錯誤分類供上層處理。"""
    return IdentificationResult(decision="unverifiable", request_id=request_id,
                                errors=[IdentificationIssue(code=code, reason=reason)])


class PlatformIdentifier:
    """綁定到一份明確 registry 與設定快照，與 I 共用 URL／query／route 規則。"""

    def __init__(self, registry: PlatformRegistry, bindings: BindingConfig):
        """綁定已載入契約並複製部署設定，避免外部修改原模型而影響後續識別。"""
        self.registry = registry
        # 避免呼叫者修改原 model 後悄悄變更這個 instance 的部署設定。
        self.bindings = BindingConfig.model_validate(bindings.model_dump(mode="json"))

    @classmethod
    def from_paths(cls, platforms_dir: Path, bindings_file: Path):
        """只讀取明確本地設定；來源／hash 無效時不跳過壞掉的契約。"""
        bindings = BindingConfig.model_validate(read_yaml(bindings_file.read_bytes()))
        return cls(PlatformRegistry(platforms_dir), bindings)

    def identify(self, request_url: str, request_method: str, *,
                 context: RuntimeContext | None = None) -> IdentificationResult:
        """由原始 URL 與明確 method 識別；歧義、未審 query 或版本不符均拒絕。"""
        try:
            if request_method not in METHODS:
                return _failure("unsupported_method", "沒有明確支援此 HTTP method")
            url = parse_request_url(request_url)
            selected_bindings = []
            trusted = RuntimeContext.model_validate(context.model_dump()) if context is not None else None
            for binding in self.bindings.bindings:
                if trusted is not None and any(getattr(binding, key) != value for key, value in trusted.model_dump().items()):
                    continue
                if match_base_url(url, binding.base_url) is not None:
                    selected_bindings.append(binding)
            # disabled 的重疊設定也不會被默默略過而回退到另一份版本。
            if len(selected_bindings) != 1:
                return _failure("binding_not_unique", "找不到唯一的環境／部署／站點綁定")
            binding = selected_bindings[0]
            if not binding.enabled:
                return _failure("binding_disabled", "此部署綁定尚未啟用")

            # 與 I 使用完全相同的 registry 選擇，不用 runtime context 隱藏契約歧義。
            site = select_site(self.registry.bundles, url)
            manifest = site.bundle.manifest
            expected = (binding.platform_id, binding.platform_version, binding.spec_sha256,
                        base_identity(binding.base_url))
            actual = (manifest.platform_id, manifest.platform_version, manifest.spec_sha256,
                      base_identity(site.base_url))
            if expected != actual:
                return _failure("binding_contract_mismatch", "部署綁定的平台、版本、hash 或 base URL 與載入契約不符")
            if not manifest.approved:
                return _failure("contract_not_approved", "此規格尚未完成來源與適用範圍審查")
            query = parse_query(url.query)
            if query not in manifest.query_contexts:
                return _failure("unsupported_context", "此 query 組合尚未審查")
            relative_path = url.path[len(site.prefix):] or "/"
            selected = select_operation(site.bundle.spec, request_method, relative_path)
            operation_id = selected.operation.get("operationId", f"{request_method} {selected.template}")
            identity = IdentifiedOperation(**binding.model_dump(mode="json"),
                                           operation_id=operation_id, method=request_method, path=selected.template,
                                           path_parameters=selected.path_parameters, query=query)
            return IdentificationResult(decision="identified", identity=identity)
        except SelectionError as exc:
            return _failure(exc.code, exc.reason)
        except Exception:
            # 不回顯原始請求、憑證或本地檔名；無法可靠選擇契約時維持失敗關閉。
            return _failure("identification_error", "識別器無法確認請求身份")

    def identify_request(self, request: NormalizedRequest, *,
                         context: RuntimeContext | None = None) -> IdentificationResult:
        """A 的 decoded path 不參與重新匹配；Forwarded 或 X-Platform 也不覆寫綁定。"""
        if sum(name.lower() == "host" for name, _ in request.headers) > 1:
            return _failure("ambiguous_host", "多個 Host 無法唯一識別 origin", request.request_id)
        result = self.identify(request.raw_url, request.method, context=context)
        return result.model_copy(update={"request_id": request.request_id})
