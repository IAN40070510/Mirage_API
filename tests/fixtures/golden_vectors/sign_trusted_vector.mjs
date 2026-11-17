// 僅重建公開的測試向量。測試 seed 不可用於部署。
import assert from 'node:assert/strict';
import { createPrivateKey, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';

const vector = JSON.parse(readFileSync(new URL('./trusted_session.json', import.meta.url), 'utf8'));
const segments = [];
for (const object of [vector.header, vector.claims]) {
  // 此固定向量的兩份物件只有純量欄位，依鍵名排序並以 UTF-8 編碼。
  const json = JSON.stringify(object, Object.keys(object).sort());
  segments.push(Buffer.from(json).toString('base64url'));
}
const input = segments.join('.');
const key = createPrivateKey({
  format: 'der', type: 'pkcs8',
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 1)]),
});
const signature = sign(null, Buffer.from(input, 'ascii'), key).toString('base64url');
assert.equal(signature, vector.signature);
process.stdout.write(input + '.' + signature);
