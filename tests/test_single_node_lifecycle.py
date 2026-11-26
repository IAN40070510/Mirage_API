"""SINGLE-NODE-01：明確 opt-in 的單機 Compose 真 PostgreSQL 啟停與隔離卷測試。"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import time
from uuid import uuid4

import pytest


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deploy/single-node/compose.yaml"
ENV_EXAMPLE = ROOT / "deploy/single-node/env.example"
COMPOSE_BIN = "/usr/local/bin/docker-compose"
DOCKER_BIN = "/usr/bin/docker"


def _command(argv: list[str], *, environment: dict[str, str] | None = None,
             timeout: int = 60) -> bytes:
    """僅執行明確 argv，隱藏可能含敏感部署資訊的 stdout／stderr 失敗本文。"""
    try:
        result = subprocess.run(
            argv, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise AssertionError("single_node_isolated_compose_command_unavailable") from None
    assert result.returncode == 0, "single_node_isolated_compose_command_failed"
    assert len(result.stdout) <= 256 * 1024, "single_node_isolated_compose_output_unbounded"
    return result.stdout


def test_true_disposable_compose_postgres_lifecycle_without_external_fence(tmp_path):
    """真的啟動本輪隨機單機專案 DB，驗證 PG17、內網、持久卷和精確清理。

    故障注入只碰本次隨機專案、沒有創建受保護 Sender 或任何公開 port；
    證明 DB 子流程真實，而非將 postgres 健康檢查冒充九容器 G3b～G6 GO。
    """
    if (os.environ.get("MIRAGE_SINGLE_NODE_PG_LIFECYCLE_ISOLATED") != "true"
            or os.environ.get("MIRAGE_SINGLE_NODE_DISPOSABLE_COMPOSE_PROJECT") != "true"
            or os.environ.get("MIRAGE_G5_RESTORE_PG_TOOL_CONTAINER") != "mirage-g3b-ci-db"):
        pytest.skip("requires exact disposable ARM64 Docker and PostgreSQL opt-ins")
    project = "mirage-sn-ci-" + uuid4().hex[:12]
    assert re.fullmatch(r"mirage-sn-ci-[0-9a-f]{12}", project)
    database = "mirage_sn_ci_" + uuid4().hex[:10]
    admin = "mirage_ci_admin"
    secret_dir = tmp_path / "secrets"
    secret_dir.mkdir(mode=0o700)
    secret = secret_dir / "postgres_password"
    secret.write_text(secrets.token_urlsafe(36), encoding="utf-8")
    secret.chmod(0o400)
    env = os.environ.copy()
    env.update({
        "MIRAGE_SINGLE_NODE_IMAGE": "mirage-api:standalone",
        "MIRAGE_SINGLE_NODE_POSTGRES_IMAGE": "postgres:17.6-alpine",
        "MIRAGE_SINGLE_NODE_SECRETS_DIR": str(secret_dir),
        "MIRAGE_SINGLE_NODE_DB_NAME": database,
        "MIRAGE_SINGLE_NODE_DB_ADMIN": admin,
        "MIRAGE_SINGLE_NODE_WORLD_SCHEMA": "public",
        "MIRAGE_SINGLE_NODE_ENVIRONMENT_ID": "isolated",
        "MIRAGE_SINGLE_NODE_DEPLOYMENT_ID": "disposable",
        "MIRAGE_SINGLE_NODE_ISSUER": "disposable",
        "MIRAGE_SINGLE_NODE_AUDIENCE": "disposable",
        "MIRAGE_SINGLE_NODE_VERIFIER_LOGIN": "mirage_ci_verifier",
        "MIRAGE_SINGLE_NODE_INVENTORY_LOGIN": "mirage_ci_inventory",
        "MIRAGE_SINGLE_NODE_CART_LOGIN": "mirage_ci_cart",
        "MIRAGE_SINGLE_NODE_VALIDATOR_LOGIN": "mirage_ci_validator",
        "MIRAGE_SINGLE_NODE_PUBLISHER_READER_LOGIN": "mirage_ci_publisher_reader",
        "MIRAGE_SINGLE_NODE_PUBLISHER_WRITER_LOGIN": "mirage_ci_publisher_writer",
        "MIRAGE_SINGLE_NODE_PUBLISHER_PROMOTER_LOGIN": "mirage_ci_publisher_promoter",
        "MIRAGE_SINGLE_NODE_AUTHORIZER_LOGIN": "mirage_ci_authorizer",
        "MIRAGE_SINGLE_NODE_SENDER_LOGIN": "mirage_ci_sender",
    })
    base = [COMPOSE_BIN, "--project-name", project, "-f", str(COMPOSE)]
    # 任何未知同名 Container/Volume 不得被本測試的 down --volumes 清除。
    preexisting = _command([
        DOCKER_BIN, "ps", "-aq", "--filter", "label=com.docker.compose.project=" + project,
    ]).strip()
    assert not preexisting, "single_node_isolated_project_collision"
    preexisting_volumes = _command([
        DOCKER_BIN, "volume", "ls", "-q", "--filter",
        "label=com.docker.compose.project=" + project,
    ]).strip()
    assert not preexisting_volumes, "single_node_isolated_volume_collision"
    created = False
    try:
        _command([*base, "config", "--quiet"], environment=env)
        # up 即使中途失敗也可能已建立容器或卷；先標記只清理這個亂數專案。
        created = True
        _command([*base, "up", "--detach", "--no-deps", "postgres"],
                 environment=env, timeout=90)
        for _ in range(60):
            status = subprocess.run(
                [*base, "exec", "-T", "postgres", "pg_isready", "-h", "127.0.0.1",
                 "-U", admin, "-d", database],
                env=env, capture_output=True, timeout=15, check=False,
            )
            if status.returncode == 0:
                break
            time.sleep(0.5)
        else:
            pytest.fail("single_node_isolated_postgres_readiness_timeout")
        rows = _command([
            *base, "exec", "-T", "postgres", "psql", "-U", admin, "-d", database,
            "-Atqc", "SELECT current_database(),session_user,current_setting('server_version_num')",
        ], environment=env).decode("utf-8").strip().split("|")
        assert rows[0:2] == [database, admin] and rows[2].startswith("170")
        container_ids = _command([
            DOCKER_BIN, "ps", "-aq", "--filter", "label=com.docker.compose.project=" + project,
        ]).decode("ascii").strip().splitlines()
        assert len(container_ids) == 1 and len(container_ids[0]) >= 12
        inspected = json.loads(_command([
            DOCKER_BIN, "container", "inspect", container_ids[0],
        ]))[0]
        assert inspected["Config"]["Labels"]["com.docker.compose.service"] == "postgres"
        assert inspected["HostConfig"]["PortBindings"] in (None, {})
        names = set(inspected["NetworkSettings"]["Networks"])
        assert names == {project + "_database"}
        network = json.loads(_command([
            DOCKER_BIN, "network", "inspect", project + "_database",
        ]))[0]
        assert network["Internal"] is True
        volume = json.loads(_command([
            DOCKER_BIN, "volume", "inspect", project + "_world_data",
        ]))[0]
        assert volume["Labels"]["com.docker.compose.project"] == project
        # 真實 SQL 寫入後重啟同一容器，確認 Compose named volume 保留 World bytes。
        _command([
            *base, "exec", "-T", "postgres", "psql", "-U", admin, "-d", database,
            "-v", "ON_ERROR_STOP=1", "-c",
            "CREATE TABLE single_node_lifecycle_probe ("
            "marker integer PRIMARY KEY); INSERT INTO single_node_lifecycle_probe VALUES (73);",
        ], environment=env)
        _command([*base, "restart", "postgres"], environment=env, timeout=90)
        for _ in range(60):
            status = subprocess.run(
                [*base, "exec", "-T", "postgres", "pg_isready", "-h", "127.0.0.1",
                 "-U", admin, "-d", database],
                env=env, capture_output=True, timeout=15, check=False,
            )
            if status.returncode == 0:
                break
            time.sleep(0.5)
        else:
            pytest.fail("single_node_isolated_postgres_restart_timeout")
        persisted = _command([
            *base, "exec", "-T", "postgres", "psql", "-U", admin, "-d", database,
            "-Atqc", "SELECT marker FROM single_node_lifecycle_probe",
        ], environment=env).decode("ascii").strip()
        assert persisted == "73", "single_node_isolated_world_volume_not_persistent"
    finally:
        try:
            if created:
                # 任何前面斷言失敗都必須清理本次亂數專案；失敗不得默默略過。
                _command([*base, "down", "--volumes", "--remove-orphans"],
                         environment=env, timeout=90)
                assert not _command([
                    DOCKER_BIN, "ps", "-aq", "--filter",
                    "label=com.docker.compose.project=" + project,
                ]).strip(), "single_node_isolated_container_cleanup_incomplete"
                assert not _command([
                    DOCKER_BIN, "volume", "ls", "-q", "--filter",
                    "label=com.docker.compose.project=" + project,
                ]).strip(), "single_node_isolated_volume_cleanup_incomplete"
                assert not _command([
                    DOCKER_BIN, "network", "ls", "-q", "--filter",
                    "label=com.docker.compose.project=" + project,
                ]).strip(), "single_node_isolated_network_cleanup_incomplete"
        finally:
            # 測試 Secret 是 owner 唯讀；不要嘗試用原權限覆寫它。
            secret.unlink()
