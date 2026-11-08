# syntax=docker/dockerfile:1
# 固定 Python patch 與 Debian 系列；正式發布時另記錄映像 digest 及解析出的套件版本。
ARG PYTHON_IMAGE=python:3.13.13-slim-bookworm
FROM ${PYTHON_IMAGE} AS wheels

ENV PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY pyproject.toml ./
COPY src/ ./src/
COPY mirage_validator/ ./mirage_validator/
# 套件與相依 wheel 在建置階段解析；執行映像不保留編譯來源或下載工具。
RUN python -m pip wheel --no-cache-dir --wheel-dir /wheels .

FROM ${PYTHON_IMAGE} AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYDANTIC_AI_NO_BANNER=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    MIRAGE_DEMO_MODE=fallback \
    MIRAGE_DEMO_ORIGIN=http://127.0.0.1:8000 \
    MIRAGE_DEMO_CONFIG=/app/configs/demo.yaml \
    MIRAGE_DEMO_OUTPUT=/app/generated/demo \
    MIRAGE_LLM_CONFIG=/app/configs/llm.yaml

WORKDIR /app
COPY --from=wheels /wheels /wheels
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheels mirage-response-validator \
    && rm -rf /wheels \
    && groupadd --gid 10001 mirage \
    && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/mirage mirage \
    && mkdir -p /app/generated/demo \
    && chown -R 10001:10001 /app/generated

COPY --chown=10001:10001 configs/ ./configs/
COPY --chown=10001:10001 tools/ ./tools/
COPY --chown=10001:10001 docs/ ./docs/
COPY --chown=10001:10001 README.md ./README.md

USER 10001:10001
EXPOSE 8000
STOPSIGNAL SIGTERM

# 健康檢查只確認展示入口可回應，不把模型可用或官方平台相容性當成健康條件。
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; opener = urllib.request.build_opener(urllib.request.ProxyHandler({})); response = opener.open('http://127.0.0.1:8000/healthz', timeout=3); assert response.status == 200"]

CMD ["python", "-m", "uvicorn", "deception.api.demo:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers", "--no-server-header", "--no-date-header", "--no-access-log"]
