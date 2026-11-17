// 固定 CommitResult 互通向量的獨立核對器；不作正式授權或任意 JSON 數值的 SDK。
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const fixture = JSON.parse(readFileSync(new URL('./commit_results.json', import.meta.url), 'utf8'));
assert.equal(fixture.fixture_version, 1);
assert.equal(fixture.result_encoding_version, 1);
const hex = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const positive = value => Number.isSafeInteger(value) && value > 0;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
// 短箭頭函式分別檢查固定 hex、正安全整數與 JSON 物件，不參與身份授權。

/** 依 Unicode code point 比較鍵，避免 JavaScript UTF-16 排序把 astral 字元移到 BMP 鍵之前。 */
function compareKeys(left, right) {
  const a = Array.from(left, char => char.codePointAt(0));
  const b = Array.from(right, char => char.codePointAt(0));
  for (let index = 0; index < Math.min(a.length, b.length); index++) {
    if (a[index] !== b[index]) return a[index] - b[index];
  }
  return a.length - b.length;
}

/** 對固定安全整數／Unicode 向量獨立編碼 Python ensure_ascii=True 的緊湊排序 JSON。 */
function encode(value) {
  if (object(value)) {
    return `{${Object.keys(value).sort(compareKeys).map(key => `${encode(key)}:${encode(value[key])}`).join(',')}}`;
  }
  if (Array.isArray(value)) return `[${value.map(encode).join(',')}]`;
  if (typeof value === 'number') assert.ok(Number.isSafeInteger(value));
  return JSON.stringify(value).replace(/[\u007f-\uffff]/g,
    char => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

/** 從完整公開 DTO 獨立組合保存結果的摘要前像，重播狀態仍指向原 committed／rejected。 */
function preimage(value) {
  return encode({
    result: value.result,
    version: value.observed_state_version,
    hash: value.observed_state_hash,
    attempt: value.commit_attempt_id.toLowerCase(),
    status: ['committed', 'already_committed'].includes(value.status) ? 'committed' : 'rejected',
  });
}

/** 只判定此固定向量列出的完整 DTO 不變量，不宣稱重製完整 Pydantic 或資料庫授權流程。 */
function accepts(value) {
  const fields = new Set(['status', 'scope', 'operation', 'idempotency_key', 'commit_attempt_id',
    'result_encoding_version', 'committed_state_version', 'committed_state_hash', 'observed_state_version',
    'observed_state_hash', 'result_digest', 'result', 'failure_code', 'replayed']);
  if (Object.keys(value).some(key => !fields.has(key))) return false;
  if (!['committed', 'already_committed', 'conflict', 'rejected', 'unverifiable'].includes(value.status)) return false;
  if (!object(value.scope) || !['environment_id', 'deployment_id', 'session_id', 'world_generation_id']
    .every(key => typeof value.scope[key] === 'string' && value.scope[key].length > 0 && value.scope[key].length <= 128)) return false;
  if (![value.operation, value.idempotency_key].every(text => typeof text === 'string' && /^[A-Za-z0-9._-]{1,128}$/.test(text))) return false;
  if (typeof value.commit_attempt_id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value.commit_attempt_id)) return false;
  if (value.result_encoding_version !== 1 || typeof value.replayed !== 'boolean') return false;
  for (const prefix of ['committed', 'observed']) {
    const version = value[`${prefix}_state_version`], hash = value[`${prefix}_state_hash`];
    if ((version === null) !== (hash === null)) return false;
    if (version !== null && (!positive(version) || !hex(hash))) return false;
  }
  const success = ['committed', 'already_committed'].includes(value.status);
  if (success) {
    if (value.failure_code !== null || value.committed_state_version === null || value.result === null
        || value.result_digest === null || value.observed_state_version !== value.committed_state_version
        || value.observed_state_hash !== value.committed_state_hash
        || value.replayed !== (value.status === 'already_committed')) return false;
  } else if (value.committed_state_version !== null || typeof value.failure_code !== 'string'
      || !/^[a-z][a-z0-9_]{0,127}$/.test(value.failure_code)) return false;
  if (['conflict', 'unverifiable'].includes(value.status)
      && (value.result !== null || value.result_digest !== null || value.replayed)) return false;
  if (value.result === null) return value.result_digest === null && !value.replayed;
  if (!object(value.result) || value.observed_state_version === null || !hex(value.result_digest)) return false;
  return createHash('sha256').update(preimage(value), 'utf8').digest('hex') === value.result_digest;
}

// 逐一核對接受／拒絕及精確前像，不以同一個語言的摘要函式產生預期答案。
for (const vector of fixture.cases) {
  assert.equal(accepts(vector.outcome), vector.accepted, vector.name);
  if (vector.digest_preimage_utf8_hex !== undefined) {
    assert.equal(Buffer.from(preimage(vector.outcome), 'utf8').toString('hex'), vector.digest_preimage_utf8_hex, vector.name);
  }
}
assert.equal(fixture.cases[0].outcome.result_digest, fixture.cases[1].outcome.result_digest);
assert.equal(fixture.cases[2].outcome.result_digest, fixture.cases[3].outcome.result_digest);
process.stdout.write(`commit-result-vectors-ok:${fixture.cases.length}`);
