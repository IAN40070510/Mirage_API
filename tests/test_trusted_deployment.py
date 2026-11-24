"""部署設定格式、金鑰與固定安全政策驗收。"""

import pytest

from deception.security.trusted_deployment import TrustedDeploymentSettings


def settings(**changes):
    """建立無憑證的部署範例，允許個別測試覆寫無效欄位。"""
    values = dict(issuer="gateway", audience="mirage", environment_id="env-1",
                  deployment_id="deploy-1", source_id="detector", service_id="store",
                  site_id="shop", public_keys={"key-1": "01" * 32})
    values.update(changes)
    return TrustedDeploymentSettings(**values)


@pytest.mark.parametrize("keys", [{"key-1": "zz"}, {"key-1": "01"}, {"": "01" * 32}])
def test_deployment_rejects_invalid_keys_before_serving(keys):
    """無效 hex、公鑰長度或空 kid 必須在啟動階段拒絕。"""
    with pytest.raises(ValueError):
        settings(public_keys=keys).build_provider(postgres_dsn="postgresql://test")


@pytest.mark.parametrize("changes", [{"max_clock_skew": 31}, {"max_lifetime": 61},
                                    {"public_keys": {}}, {"issuer": ""}])
def test_deployment_rejects_policy_outside_baseline(changes):
    """部署設定不得放寬基準的期限、身份或金鑰必要條件。"""
    with pytest.raises(ValueError):
        settings(**changes)


def test_deployment_builds_provider_without_connecting_database():
    """有效設定可於啟動建立 provider，資料庫操作延至實際請求。"""
    assert callable(settings().build_provider(postgres_dsn="postgresql://test"))


def test_original_assessment_strict_mode_requires_injected_lookup():
    """嚴格接收端缺可信外部查回時必須在啟動階段拒絕，不降級為 claims-only。"""
    with pytest.raises(ValueError, match="trusted lookup"):
        settings(require_original_assessment=True).build_provider(
            postgres_dsn="postgresql://world-only"
        )
    with pytest.raises(ValueError, match="requires strict mode"):
        settings().build_provider(
            postgres_dsn="postgresql://world",
            original_lookup=lambda _id: None,
        )


def test_original_assessment_consumer_injects_trusted_lookup_without_connect():
    """嚴格模式只持有部署者傳入的查回介面，SQL 與 DB 角色由外部持有。"""
    def lookup(_assessment_id):
        """此測試刻意不建立外部連線；回傳缺失由接收端嚴格拒絕。"""
        return None
    provider = settings(require_original_assessment=True).build_provider(
        postgres_dsn="postgresql://world",
        original_lookup=lookup,
    )
    assert provider._original_lookup is lookup
    assert provider._require_original_assessment is True
