// 僅簽發固定公開測試向量；01／02 seed 絕不可用於任何部署。
import assert from 'node:assert/strict';
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';

const fixture = JSON.parse(readFileSync(new URL('./trusted_session_errors.json', import.meta.url), 'utf8'));
assert.equal(fixture.fixture_version, 1);

/** 從公開測試 seed 建立 PKCS#8 Ed25519 key，不讀取工作區或部署的任何秘密。 */
function testKey(byte) {
  return createPrivateKey({ format: 'der', type: 'pkcs8', key: Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, byte),
  ]) });
}

const privateKey = testKey(1), publicKey = createPublicKey(privateKey);
assert.equal(publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex'), fixture.public_key_hex);

/** 保留原始 JSON bytes，獨立簽發每個固定案例，包含有意無效的格式及非 canonical 編碼。 */
function issue(vector) {
  if (vector.literal) return vector.literal_token;
  const material = [vector.header_json, vector.payload_json].map(text => Buffer.from(text, 'utf8').toString('base64url')).join('.');
  const key = vector.signature_mode === 'wrong-key' ? testKey(2) : privateKey;
  const signature = sign(null, Buffer.from(material, 'ascii'), key);
  // 正確簽章的格式負例仍有有效 crypto bytes，Python 必須因格式拒絕，而非偶然簽章壞掉。
  assert.equal(verify(null, Buffer.from(material, 'ascii'), publicKey, signature), vector.signature_mode !== 'wrong-key');
  let encoded = signature.toString('base64url');
  if (vector.signature_mode === 'padded') encoded += '=';
  if (vector.signature_mode === 'noncanonical') {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    encoded = encoded.slice(0, -1) + alphabet[alphabet.indexOf(encoded.at(-1)) + 1];
    assert.deepEqual(Buffer.from(encoded, 'base64url'), signature);
  }
  return `${material}.${encoded}`;
}

// Node 只簽發並核對 wire，不模擬 Mirage 的授權政策或 Replay 儲存。
const tokens = fixture.cases.map(vector => {
  const token = issue(vector);
  assert.deepEqual(token, vector.token, vector.name);
  return { name: vector.name, token };
});
process.stdout.write(JSON.stringify({ cases: tokens.length, public_key_hex: fixture.public_key_hex, tokens }));
