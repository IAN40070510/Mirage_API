// 獨立驗收固定跨語言向量的來源、核准鏈及期限；不是可用於正式授權的 SDK。
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const fixture = JSON.parse(readFileSync(new URL('./admission_projection.json', import.meta.url), 'utf8'));
assert.equal(fixture.fixture_version, 1);

// 此固定世界政策只含物件、字串及安全整數；逐層排序鍵後獨立重算政策與快照摘要。
function canonical(value) {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  }
  if (Array.isArray(value)) return value.map(canonical);
  return value;
}
const hash = value => createHash('sha256').update(JSON.stringify(canonical(value)), 'utf8').digest('hex');
const { compatibility_profile_hash, ...policy } = fixture.world_policy;
assert.equal(hash(policy), compatibility_profile_hash);
assert.equal(hash(fixture.world_state), fixture.world_state_sha256);
assert.deepEqual(fixture.world_state._mirage_world_compatibility, fixture.world_policy);

// 只核對這組向量列出的協定不變量；不聲稱完整重製 Pydantic 的所有欄位驗證。
function accepts(admission) {
  const evidence = admission.projection_evidence;
  const profile = evidence.compatibility_profile;
  const source = admission.source;
  if (admission.hash_encoding_version !== 1 || admission.candidate_serialization_version !== 1) return false;
  if (admission.transmission_deadline < admission.authorization_deadline) return false;
  if (evidence.source_spec_sha256 !== profile.source_spec_sha256) return false;
  if (evidence.projection_contract_hash !== admission.projection_contract_hash) return false;
  if (evidence.effective_projection_valid !== true) return false;
  if (evidence.official_schema_valid === false) {
    const approval = evidence.deviation_approval;
    if (!approval || approval.source_spec_sha256 !== evidence.source_spec_sha256
        || approval.projection_contract_hash !== evidence.projection_contract_hash
        || approval.approved_profile_sha256 !== profile.profile_sha256) return false;
  }
  if (!['snapshot', 'committed_operation', 'security_error'].includes(source.kind)) return false;
  if (source.kind !== 'security_error' && source.world_generation_id !== admission.world_generation_id) return false;
  if (source.kind === 'committed_operation') {
    if (typeof source.operation_result_digest !== 'string' || !/^[0-9a-f]{64}$/.test(source.operation_result_digest)) return false;
    if (!Number.isSafeInteger(source.committed_state_version) || source.committed_state_version < 1) return false;
    if (typeof source.committed_state_hash !== 'string' || !/^[0-9a-f]{64}$/.test(source.committed_state_hash)) return false;
  }
  return true;
}

// 逐個固定案例比較，並回報數量，避免少讀 fixture 仍得到成功訊息。
for (const vector of fixture.cases) {
  assert.equal(accepts(vector.admission), vector.accepted, vector.name);
}
process.stdout.write(`admission-projection-vectors-ok:${fixture.cases.length}`);
