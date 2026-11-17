"""保存固定分類的可信入口拒絕事件，不接收訪客資料或憑證。"""

from uuid import uuid4


STAGES = frozenset({"trusted_ingress", "resource_binding", "world_resolve", "read_admission", "response_pipeline"})
REASONS = frozenset({"unavailable", "read_only_policy", "authorization_expired", "resource_scope_mismatch"})


class PostgresIngressAudit:
    """以獨立交易記錄入口拒絕；失敗向上傳遞，不把未保存當成成功。"""

    def __init__(self, dsn: str, *, environment_id: str, deployment_id: str):
        """保存部署端固定的資料庫與隔離範圍，不接受請求提供的 scope。"""
        if any(not isinstance(value, str) or not value.strip() for value in (dsn, environment_id, deployment_id)):
            raise ValueError("ingress audit requires fixed deployment settings")
        self._dsn = dsn
        self._environment_id = environment_id
        self._deployment_id = deployment_id

    def record_refusal(self, *, stage: str, reason: str) -> str:
        """提交一筆固定分類事件並回傳伺服器 UUID；分類無效或資料庫故障時拋錯，不重試。"""
        if stage not in STAGES or reason not in REASONS:
            raise ValueError("invalid ingress audit classification")
        import psycopg

        event_id = str(uuid4())
        with psycopg.connect(self._dsn, connect_timeout=5) as connection:
            connection.execute("SET LOCAL statement_timeout='5s'")
            connection.execute("INSERT INTO ingress_refusal_audit "
                "(event_id,environment_id,deployment_id,stage,reason) VALUES (%s,%s,%s,%s,%s)",
                (event_id, self._environment_id, self._deployment_id, stage, reason))
        return event_id
