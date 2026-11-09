"""離線情境展示的領域派送、相容入口與實際電商一致性回歸。"""

import hashlib
import importlib
import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from deception.domains.ecommerce.scenario_demo import run_demo
from deception.domains.registry import DomainImplementation, DomainImplementations
from deception.scenarios import __main__ as scenario_cli


def _unused_adapter(*args, **kwargs):
    """填入測試插件不會使用的必要介面，若意外派送到此則立即使測試失敗。"""
    raise AssertionError("The offline CLI invoked an unrelated domain interface")


def _helpdesk_implementation(scenario_demo=None):
    """建立不依賴商品模型的工單插件，並保留舊位置參數建構方式。"""
    implementation = DomainImplementation("helpdesk", _unused_adapter, _unused_adapter,
                                          _unused_adapter, _unused_adapter, _unused_adapter)
    return replace(implementation, scenario_demo=scenario_demo)


def _set_cli(monkeypatch, implementations, *arguments):
    """注入獨立插件表與命令列參數，確保測試不讀取或改寫全域領域設定。"""
    def registry_factory():
        """把本案例的插件表交給共用命令列，供派送與拒絕行為斷言使用。"""
        return DomainImplementations(implementations)

    monkeypatch.setattr(scenario_cli, "default_implementations", registry_factory)
    monkeypatch.setattr(sys, "argv", ["deception.scenarios", *arguments])


def test_ecommerce_scenario_demo_preserves_real_contract_and_snapshot_checks(tmp_path):
    """執行真實離線管線，確認三次回應均通過契約且報告摘要依實際 bytes 計算。"""
    output = run_demo(tmp_path, domain="ecommerce")
    raw = output.read_bytes()
    report = json.loads(raw)
    assert output.parent == tmp_path / "scenarios"
    assert output.name == hashlib.sha256(raw).hexdigest() + ".json"
    assert report["test_only"] is True
    assert report["domain"] == "ecommerce"
    assert report["checks"] == {
        "all_candidates_passed_synthetic_gate": True,
        "e_snapshot_unchanged": True,
        "repeat_product_body_identical": True,
        "outcome_statuses": [200, 404, 200],
    }
    assert [item["candidate"]["status_code"] for item in report["results"]] == [200, 404, 200]
    assert all(item["gate"]["decision"] == "pass" and item["gate"]["valid"] is True
               for item in report["results"])
    assert report["results"][0]["candidate"]["body"] == report["results"][2]["candidate"]["body"]
    assert {"contract", "contract_source", "scope", "policy", "policy_sha256", "dataset_config",
            "dataset_namespace", "state_sha256", "generated_at"} <= report.keys()


def test_old_scenario_demo_import_resolves_to_canonical_domain_function():
    """確認既有 run_demo 匯入仍指向同一份電商實作，避免相容層留下第二份商品流程。"""
    compatibility = importlib.import_module("deception.scenarios.demo")
    assert compatibility.run_demo is run_demo
    with pytest.raises(AttributeError):
        getattr(compatibility, "unknown_adapter")


@pytest.mark.parametrize("domain", ["helpdesk", "unknown", None])
def test_direct_ecommerce_demo_rejects_other_or_missing_domain(tmp_path, domain):
    """領域專屬入口也須拒絕錯誤或未提供的 ID，不能以商品流程處理其他領域。"""
    with pytest.raises(ValueError, match="ecommerce only"):
        run_demo(tmp_path, domain=domain)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("explicit_output", [None, "custom-output"])
def test_cli_dispatches_noncommerce_demo_and_domain_output(monkeypatch, tmp_path, capsys, explicit_output):
    """以工單 callback 驗證共用 CLI 僅派送所選領域，且預設輸出依該領域隔離。"""
    calls = []

    def ticket_demo(output_root, *, domain):
        """寫入工單專屬報告並記錄路徑，驗證共用入口沒有商品查詢或狀態碼假設。"""
        calls.append((output_root, domain))
        output = output_root / "scenarios" / "ticket-report.json"
        output.parent.mkdir(parents=True)
        output.write_text('{"ticket": "created"}\n', encoding="utf-8")
        return output

    arguments = ["--demo", "--domain", "helpdesk"]
    if explicit_output is not None:
        arguments.extend(["--output", explicit_output])
    _set_cli(monkeypatch, [_helpdesk_implementation(ticket_demo)], *arguments)
    monkeypatch.chdir(tmp_path)
    scenario_cli.main()
    expected_root = Path(explicit_output) if explicit_output is not None else Path("generated/domains/helpdesk")
    assert calls == [(expected_root, "helpdesk")]
    assert (tmp_path / expected_root / "scenarios/ticket-report.json").is_file()
    message = capsys.readouterr().out
    assert "Domain: helpdesk" in message
    assert "completed" in message
    assert "product" not in message
    assert "200" not in message
    assert "404" not in message


@pytest.mark.parametrize("arguments,exit_code,error", [
    (["--demo"], 2, "--demo --domain"),
    (["--demo", "--domain", "unknown"], 1, "not registered"),
    (["--demo", "--domain", "helpdesk"], 1, "no registered offline scenario"),
])
def test_cli_rejects_missing_unknown_or_unsupported_domain(monkeypatch, capsys, arguments, exit_code, error):
    """缺少領域、未知領域或未註冊展示均拒絕，不呼叫電商或其他必要介面。"""
    _set_cli(monkeypatch, [_helpdesk_implementation()], *arguments)
    with pytest.raises(SystemExit) as failure:
        scenario_cli.main()
    assert failure.value.code == exit_code
    assert error in capsys.readouterr().err


def test_cli_lists_implementation_domains_without_running_a_demo(monkeypatch, capsys):
    """領域清單由插件表提供，即使插件沒有離線展示也不觸發其他必要介面。"""
    _set_cli(monkeypatch, [_helpdesk_implementation()], "--list-domains")
    scenario_cli.main()
    assert capsys.readouterr().out == "helpdesk\n"


def test_optional_demo_keeps_previous_construction_and_rejects_noncallable():
    """舊位置參數建構可省略展示；註冊表拒絕誤填不可呼叫的可選入口。"""
    implementation = _helpdesk_implementation()
    assert implementation.scenario_demo is None
    assert DomainImplementations([implementation]).get("helpdesk") is implementation
    with pytest.raises(ValueError, match="registered interfaces"):
        DomainImplementations([replace(implementation, scenario_demo="untrusted.module")])
