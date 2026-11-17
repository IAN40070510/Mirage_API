"""共用提交結果的固定公開 JSON、Unicode 編碼與獨立 Node 互通驗收。"""

import json
from pathlib import Path
import shutil
import subprocess

from pydantic import ValidationError
import pytest

from deception.world import CommitResult
from deception.world.commit import operation_result_digest


def commit_vectors():
    """載入版本固定的七組合法結果及二十三組矛盾證據，不在測試執行時重產預期摘要。"""
    path = Path(__file__).parent / "fixtures/golden_vectors/commit_results.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("vector", commit_vectors()["cases"], ids=[row["name"] for row in commit_vectors()["cases"]])
def test_commit_result_fixed_interchange_vectors(vector):
    """公開 JSON 往返保留五類結果，拒絕矛盾版本、摘要、重播旗標及未知編碼。"""
    encoded = json.dumps(vector["outcome"], ensure_ascii=True)
    if not vector["accepted"]:
        with pytest.raises(ValidationError):
            CommitResult.model_validate_json(encoded)
        return
    outcome = CommitResult.model_validate_json(encoded)
    assert outcome.model_dump(mode="json") == vector["outcome"]
    if outcome.result is not None:
        status = "committed" if outcome.status in {"committed", "already_committed"} else "rejected"
        assert operation_result_digest(outcome.result, outcome.observed_state_version, outcome.observed_state_hash,
            outcome.commit_attempt_id, status) == outcome.result_digest
        material = dict(result=outcome.result, version=outcome.observed_state_version, hash=outcome.observed_state_hash,
                        attempt=str(outcome.commit_attempt_id), status=status)
        preimage = json.dumps(material, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)
        assert preimage.encode().hex() == vector["digest_preimage_utf8_hex"]


def test_commit_vectors_match_independent_node_encoder_and_result_rules():
    """Node 獨立處理 Unicode 鍵排序與 ASCII 跳脫，核對同一份摘要前像及所有接受／拒絕結果。"""
    node = shutil.which("node")
    if node is None:
        pytest.skip("requires Node.js for independent commit result vectors")
    script = Path(__file__).parent / "fixtures/golden_vectors/verify_commit_results.mjs"
    result = subprocess.run([node, str(script)], check=True, capture_output=True, text=True, timeout=10)
    assert result.stdout == f"commit-result-vectors-ok:{len(commit_vectors()['cases'])}"
