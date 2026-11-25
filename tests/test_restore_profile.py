"""D-74 配置契約：單機正常啟動不需 Fence；選配外部權威拒絕降級。"""

import pytest

from deception.security.restore_profile import (
    RestoreDeploymentProfile, RestoreProfileConfigurationError, load_restore_profile,
)


def test_standard_profile_has_no_external_install_requirement():
    """只給明確單機 Profile 與版本就能解析且永不聲稱整機抗回滾。"""
    profile = load_restore_profile({"MIRAGE_RESTORE_PROFILE": "standard_single_node",
                                    "MIRAGE_RESTORE_PROFILE_VERSION": "1"})
    assert profile == RestoreDeploymentProfile(
        name="standard_single_node", contract_version=1, whole_host_rollback_guarantee=False)


@pytest.mark.parametrize("environment", [
    {},
    {"MIRAGE_RESTORE_PROFILE": "standard_single_node"},
    {"MIRAGE_RESTORE_PROFILE": "standard_single_node", "MIRAGE_RESTORE_PROFILE_VERSION": "2"},
    {"MIRAGE_RESTORE_PROFILE": "fallback", "MIRAGE_RESTORE_PROFILE_VERSION": "1"},
    {"MIRAGE_RESTORE_PROFILE": "external_fence", "MIRAGE_RESTORE_PROFILE_VERSION": "1"},
])
def test_ambiguous_or_incomplete_selection_is_rejected(environment):
    """缺少契約版本、模式無效或外部參數不完整，均拒絕部署而非退回單機。"""
    with pytest.raises(RestoreProfileConfigurationError):
        load_restore_profile(environment)


@pytest.mark.parametrize("value", ["", "postgresql://fence.example/authority"])
def test_external_fence_fields_cannot_be_silently_ignored_in_standard_mode(value):
    """殘留外部權威設定即使空值也代表模式不一致，禁止靜默降級。"""
    with pytest.raises(RestoreProfileConfigurationError, match="downgrade_refused"):
        load_restore_profile({"MIRAGE_RESTORE_PROFILE": "standard_single_node",
                              "MIRAGE_RESTORE_PROFILE_VERSION": "1",
                              "MIRAGE_FENCE_AUTHORITY_DSN": value})


def test_external_profile_pins_independent_public_keys_without_publishing_dsn(tmp_path):
    """外部模式需完整 namespace／epoch／獨立簽章鍵，不能洩漏 DSN 密碼。"""
    publisher, head = tmp_path / "publisher.pub", tmp_path / "head.pub"
    publisher.write_text("01" * 32, encoding="ascii")
    head.write_text("02" * 32, encoding="ascii")
    config = {
        "MIRAGE_RESTORE_PROFILE": "external_fence", "MIRAGE_RESTORE_PROFILE_VERSION": "1",
        "MIRAGE_FENCE_AUTHORITY_DSN": "postgresql://fence:secret@localhost/isolated",
        "MIRAGE_FENCE_NAMESPACE": "mirage.test", "MIRAGE_FENCE_EPOCH": "epoch-1",
        "MIRAGE_FENCE_PUBLISHER_PUBLIC_KEY_FILE": str(publisher),
        "MIRAGE_FENCE_HEAD_PUBLIC_KEY_FILE": str(head),
    }
    parsed = load_restore_profile(config)
    assert parsed.name == "external_fence" and parsed.fence_namespace == "mirage.test"
    assert parsed.publisher_key_digest != parsed.head_key_digest
    assert not parsed.whole_host_rollback_guarantee
    assert "secret" not in repr(parsed) and "isolated" not in repr(parsed)
    head.write_text("01" * 32, encoding="ascii")
    with pytest.raises(RestoreProfileConfigurationError, match="external_pin_invalid"):
        load_restore_profile(config)


def test_bad_external_key_does_not_disclose_path_or_enable_fallback(tmp_path):
    """金鑰損毀仍封閉且固定錯誤，不能繼續當成單機模式。"""
    bad = tmp_path / "PRIVATE-SHOULD-NOT-LEAK.pub"
    bad.write_text("not-a-key", encoding="ascii")
    config = {
        "MIRAGE_RESTORE_PROFILE": "external_fence", "MIRAGE_RESTORE_PROFILE_VERSION": "1",
        "MIRAGE_FENCE_AUTHORITY_DSN": "postgresql://fence:secret@localhost/isolated",
        "MIRAGE_FENCE_NAMESPACE": "mirage.test", "MIRAGE_FENCE_EPOCH": "epoch-1",
        "MIRAGE_FENCE_PUBLISHER_PUBLIC_KEY_FILE": str(bad),
        "MIRAGE_FENCE_HEAD_PUBLIC_KEY_FILE": str(bad),
    }
    with pytest.raises(RestoreProfileConfigurationError) as raised:
        load_restore_profile(config)
    assert "PRIVATE-SHOULD-NOT-LEAK" not in str(raised.value)
    assert "secret" not in str(raised.value)


def test_profile_claim_cannot_be_forged_by_direct_construction():
    """不允許任何部署模式自行宣稱未經驗證的 Host Rollback 保證。"""
    with pytest.raises(RestoreProfileConfigurationError, match="contract_invalid"):
        RestoreDeploymentProfile("standard_single_node", 1, True)
