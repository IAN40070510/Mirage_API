// 使用 Node.js 獨立核對長度前綴 v1、UTF-8 body 與 ordered headers 的跨語言向量。
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const vector = JSON.parse(readFileSync(new URL('./response_transport.json', import.meta.url), 'utf8'));
// 每一欄以 8-byte big-endian 長度前綴串接，空值也佔一個長度欄位。
const fields = (...parts) => Buffer.concat(parts.flatMap(part => {
  const size = Buffer.alloc(8);
  size.writeBigUInt64BE(BigInt(part.length));
  return [size, part];
}));
const headers = fields(...vector.headers.map(([name, value]) =>
  fields(Buffer.from(name.toLowerCase(), 'ascii'), Buffer.from(value, 'latin1'))));
const body = Buffer.from(vector.body, 'utf8');
const envelope = fields(Buffer.from('1'), Buffer.from(String(vector.status)), headers, body);
// 對精確 bytes 計算 SHA-256，不重新序列化內容。
const hash = data => createHash('sha256').update(data).digest('hex');
assert.equal(envelope.toString('hex'), vector.envelope_hex);
assert.equal(hash(envelope), vector.candidate_hash);
assert.equal(hash(body), vector.body_hash);
assert.equal(hash(headers), vector.semantic_headers_hash);
process.stdout.write('transport-vector-ok');
