"""可選的 A→C/N→M 接入；安全判定及執行設定只能由伺服器明確注入。"""

import asyncio
import inspect
import math
import time
from collections.abc import Awaitable, Callable
from datetime import datetime

from fastapi import FastAPI
from fastapi.responses import Response

from deception.core.renderer import ResponseRenderer
from deception.scenarios.models import AttackAssessment
from deception.generation import ContentLifecycle

from .app import RequestHandler, create_app as create_ingress_app
from .ingress import MAX_BODY_BYTES, NormalizedRequest
from .fingerprint import fingerprint_request

AssessmentProvider = Callable[[NormalizedRequest], AttackAssessment | Awaitable[AttackAssessment]]
ContentLifecycleProvider = Callable[[NormalizedRequest, AttackAssessment], ContentLifecycle | Awaitable[ContentLifecycle]]


def _unavailable(request: NormalizedRequest, *, not_applicable: bool = False) -> Response:
    """以獨立固定 Renderer 核對拒絕模板及原請求，不讀取世界、資料庫或私有錯誤內容。"""
    from deception.core.security_error import SecurityErrorRenderer

    return SecurityErrorRenderer().render(request, not_applicable=not_applicable)


def make_pipeline_handler(
    orchestrator, *, runtime, generation_config, assessment_provider: AssessmentProvider,
    dataset=None, renderer=None, now: datetime | None = None, allow_unreviewed: bool = False,
    assessment_timeout_seconds: float = 15.0,
    content_lifecycle_provider: ContentLifecycleProvider | None = None,
) -> RequestHandler:
    """綁定管理者的 C/M 依賴與可信判定供應器，產生 A 使用的非同步 handler。

    provider 可同步或非同步，但必須回傳 AttackAssessment；它負責外部來源認證，
    C/F 再核對請求關聯及有效期限。此介面不從 HTTP 欄位自行取得 verdict。
    now 僅供明確注入時鐘；正式預設使用即時時鐘。取消會原樣傳遞。
    判定期限由管理者設定；同步 provider 不能中途強制中斷，但逾期返回也不會進入 C。
    """
    if not callable(assessment_provider):
        raise ValueError("A trusted assessment provider must be explicitly supplied")
    if content_lifecycle_provider is not None and not callable(content_lifecycle_provider):
        raise ValueError("Content lifecycle provider must be server supplied")
    if (type(assessment_timeout_seconds) not in (int, float)
            or not 0 < assessment_timeout_seconds <= 120
            or not math.isfinite(assessment_timeout_seconds)):
        raise ValueError("assessment_timeout_seconds must be finite and greater than 0 and at most 120")
    selected_renderer = ResponseRenderer(orchestrator.gate) if renderer is None else renderer
    if not callable(getattr(selected_renderer, "render", None)):
        raise ValueError("The pipeline renderer must provide a render method")

    async def handle(request: NormalizedRequest) -> Response:
        """取得本次可信判定後執行 C，再由 M 驗證及回送；失敗僅提供固定診斷。"""
        try:
            deadline = time.monotonic() + assessment_timeout_seconds
            async with asyncio.timeout(assessment_timeout_seconds):
                assessment = assessment_provider(request)
                if inspect.isawaitable(assessment):
                    assessment = await assessment
            # 同步 provider 可能阻塞事件迴圈，必須主動檢查期限，不能只等待取消 callback。
            if time.monotonic() >= deadline:
                raise TimeoutError("Assessment provider exceeded its configured deadline")
            if not isinstance(assessment, AttackAssessment):
                raise ValueError("The assessment provider must return an AttackAssessment")
            # 重新驗證既有模型，避免 model_copy 的未檢查更新跨越整合邊界。
            assessment = AttackAssessment.model_validate(assessment.model_dump(mode="python"))
            extra = {}
            if content_lifecycle_provider is not None and assessment.verdict == "malicious":
                if (assessment.request_id != request.request_id or
                        assessment.request_fingerprint != fingerprint_request(request) or
                        assessment.environment_id != runtime.environment_id or
                        assessment.deployment_id != runtime.deployment_id):
                    raise ValueError("Assessment does not bind the lifecycle request")
                async with asyncio.timeout(max(0, deadline - time.monotonic())):
                    lifecycle = content_lifecycle_provider(request, assessment)
                    if inspect.isawaitable(lifecycle):
                        lifecycle = await lifecycle
                if time.monotonic() >= deadline or not isinstance(lifecycle, ContentLifecycle):
                    raise ValueError("Content lifecycle provider did not return a timely trusted binding")
                extra["content_lifecycle"] = ContentLifecycle.model_validate(lifecycle.model_dump(mode="json"))
            result = await orchestrator.run(
                request, assessment, runtime=runtime, generation_config=generation_config,
                dataset=dataset, now=now, allow_unreviewed=allow_unreviewed, **extra,
            )
            if result.decision == "not_applicable":
                return _unavailable(request, not_applicable=True)
            if result.decision != "validated":
                return _unavailable(request)
            response = selected_renderer.render(result, request)
            if not isinstance(response, Response):
                raise ValueError("The renderer did not return an HTTP response")
            return response
        except asyncio.CancelledError:
            raise
        except Exception:
            return _unavailable(request)

    return handle


def create_app(
    orchestrator, *, runtime, generation_config, assessment_provider: AssessmentProvider,
    dataset=None, renderer=None, now: datetime | None = None, allow_unreviewed: bool = False,
    max_body_bytes: int = MAX_BODY_BYTES,
    assessment_timeout_seconds: float = 15.0,
    content_lifecycle_provider: ContentLifecycleProvider | None = None,
) -> FastAPI:
    """建立可選的完整 HTTP app；不自動核准來源、建立判定服務或轉送正常流量。"""
    handler = make_pipeline_handler(
        orchestrator, runtime=runtime, generation_config=generation_config,
        assessment_provider=assessment_provider, dataset=dataset, renderer=renderer,
        now=now, allow_unreviewed=allow_unreviewed,
        assessment_timeout_seconds=assessment_timeout_seconds,
        content_lifecycle_provider=content_lifecycle_provider,
    )
    return create_ingress_app(handler=handler, max_body_bytes=max_body_bytes)
