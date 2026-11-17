// 獨立重算固定 normalized snapshot；不把預先計算的摘要交給 JWS 當作驗證。
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const fixture = JSON.parse(readFileSync(new URL('./request_fingerprint.json', import.meta.url), 'utf8'));
assert.equal(fixture.canonicalization_version, 1);
const approved = new Set(['host', 'content-type', 'content-length', 'x-request-id', 'authorization',
                          'idempotency-key', 'x-publishable-api-key']);
// SHA-256 的輸入為精確 bytes，Authorization 先依 wire Latin-1 bytes 取摘要。
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
for (const vector of fixture.cases) {
  const input = vector.request;
  const headers = [], seen = new Set();
  let error;
  for (const [originalName, originalValue] of input.headers) {
    const name = originalName.toLowerCase();
    if (!approved.has(name)) continue;
    if (seen.has(name)) { error = 'ambiguous_request_fingerprint_header'; break; }
    seen.add(name);
    headers.push([name, name === 'authorization' ? sha(Buffer.from(originalValue, 'latin1')) : originalValue]);
  }
  if (vector.error) { assert.equal(error, vector.error, vector.name); continue; }
  assert.equal(error, undefined, vector.name);
  const value = {
    request_id: input.request_id, method: input.method, raw_url: input.raw_url,
    path: input.path, raw_path: input.raw_path, query_string: input.query_string,
    query: input.query, headers, body_sha256: sha(Buffer.from(input.body, 'hex')),
  };
  // v1 固定封套的欄位鍵皆為 ASCII；陣列與重複 query／header 順序不排序。
  const ordered = Object.fromEntries(Object.keys(value).sort().map(key => [key, value[key]]));
  assert.equal(sha(Buffer.from(JSON.stringify(ordered), 'utf8')), vector.fingerprint, vector.name);
}
process.stdout.write('request-fingerprint-vectors-ok');
