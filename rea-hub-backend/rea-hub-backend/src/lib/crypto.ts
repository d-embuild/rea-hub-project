import crypto from 'crypto';
import { env } from '../config/env';

const PII_KEY = Buffer.from(env.PII_ENCRYPTION_KEY, 'base64');
const b64u = (b: Buffer) => b.toString('base64url');
const hmac = (secret: string, data: string) => crypto.createHmac('sha256', secret).update(data).digest();

function safeEqual(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ── AES-256-GCM for PII at rest: iv(12) | tag(16) | ciphertext ──
export function encryptPII(plain: string): Buffer {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', PII_KEY, iv);
  const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]);
}
export function decryptPII(buf: Buffer): string {
  const d = crypto.createDecipheriv('aes-256-gcm', PII_KEY, buf.subarray(0, 12));
  d.setAuthTag(buf.subarray(12, 28));
  return Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString('utf8');
}
export const hashPII = (v: string) => crypto.createHmac('sha256', env.PII_HASH_KEY).update(v).digest('hex');

// ── Smart Tag codes: REA-<16 char serial>-<10 char signature> ──
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // Crockford base32
function base32(buf: Buffer): string {
  let bits = 0, value = 0, out = '';
  for (const byte of buf) {
    value = ((value << 8) | byte) & 0xffff; bits += 8;
    while (bits >= 5) { out += ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}
export const newSerial = () => base32(crypto.randomBytes(10)).slice(0, 16);
const tagSig = (serial: string) => base32(hmac(env.TAG_SIGNING_SECRET, serial)).slice(0, 10);
export const formatTagCode = (serial: string) => `REA-${serial}-${tagSig(serial)}`;

/** Returns the serial if the printed code carries a valid signature, else null (blocks guessing before any DB hit). */
export function parseTagCode(raw: string): string | null {
  const m = /^REA-([0-9A-Z]{16})-([0-9A-Z]{10})$/.exec(raw.trim().toUpperCase());
  if (!m) return null;
  return safeEqual(Buffer.from(m[2]), Buffer.from(tagSig(m[1]))) ? m[1] : null;
}

// ── Dynamic QR: v1.<base64url(json)>.<base64url(hmac)> ──
export const QR_TTL_SECONDS = 45;
const SKEW_SECONDS = 3;
export interface QrPayload { v: 1; tid: string; iat: number; exp: number; n: string }

export function signQr(tagId: string, now = Math.floor(Date.now() / 1000)) {
  const payload: QrPayload = { v: 1, tid: tagId, iat: now, exp: now + QR_TTL_SECONDS, n: b64u(crypto.randomBytes(16)) };
  const body = b64u(Buffer.from(JSON.stringify(payload)));
  return { token: `v1.${body}.${b64u(hmac(env.QR_HMAC_SECRET, `v1.${body}`))}`, payload };
}

export type QrResult = { ok: true; payload: QrPayload } | { ok: false; reason: 'MALFORMED' | 'BAD_SIGNATURE' | 'EXPIRED' };
export function verifyQr(token: string): QrResult {
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== 'v1') return { ok: false, reason: 'MALFORMED' };
  const expected = hmac(env.QR_HMAC_SECRET, `v1.${parts[1]}`);
  if (!safeEqual(Buffer.from(parts[2], 'base64url'), expected)) return { ok: false, reason: 'BAD_SIGNATURE' };
  let p: QrPayload;
  try { p = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')); } catch { return { ok: false, reason: 'MALFORMED' }; }
  const now = Math.floor(Date.now() / 1000);
  if (typeof p.exp !== 'number' || typeof p.iat !== 'number' || typeof p.tid !== 'string' || typeof p.n !== 'string') return { ok: false, reason: 'MALFORMED' };
  if (now > p.exp + SKEW_SECONDS || p.iat > now + SKEW_SECONDS) return { ok: false, reason: 'EXPIRED' };
  return { ok: true, payload: p };
}
