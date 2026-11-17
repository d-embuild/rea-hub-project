import { beforeAll, describe, expect, it } from 'vitest';

let c: typeof import('../src/lib/crypto');
beforeAll(async () => {
  Object.assign(process.env, {
    DATABASE_URL: 'postgres://x', SUPABASE_URL: 'https://x.supabase.co', SUPABASE_SERVICE_ROLE_KEY: 'x', SUPABASE_JWT_SECRET: 'x',
    QR_HMAC_SECRET: 'q'.repeat(40), TAG_SIGNING_SECRET: 't'.repeat(40), PII_HASH_KEY: 'h'.repeat(40),
    PII_ENCRYPTION_KEY: Buffer.alloc(32, 7).toString('base64'),
  });
  c = await import('../src/lib/crypto');
});

describe('rotating QR (anti-screenshot)', () => {
  it('accepts a fresh token', () => {
    const { token } = c.signQr('tag-1');
    const r = c.verifyQr(token);
    expect(r.ok && r.payload.tid).toBe('tag-1');
  });
  it('rejects an expired token (a screenshot taken >45s ago)', () => {
    const { token } = c.signQr('tag-1', Math.floor(Date.now() / 1000) - 120);
    expect(c.verifyQr(token)).toEqual({ ok: false, reason: 'EXPIRED' });
  });
  it('rejects a tampered payload', () => {
    const [v, body, sig] = c.signQr('tag-1').token.split('.');
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    p.tid = 'tag-2';
    const forged = [v, Buffer.from(JSON.stringify(p)).toString('base64url'), sig].join('.');
    expect(c.verifyQr(forged)).toEqual({ ok: false, reason: 'BAD_SIGNATURE' });
  });
  it('rejects garbage', () => {
    expect(c.verifyQr('nope')).toEqual({ ok: false, reason: 'MALFORMED' });
  });
  it('gives every token a unique nonce', () => {
    expect(c.signQr('t').payload.n).not.toBe(c.signQr('t').payload.n);
  });
});

describe('smart tag codes', () => {
  it('round-trips a signed code', () => {
    const s = c.newSerial();
    expect(s).toHaveLength(16);
    expect(c.parseTagCode(c.formatTagCode(s))).toBe(s);
  });
  it('rejects a code with a wrong signature', () => {
    const code = c.formatTagCode(c.newSerial());
    expect(c.parseTagCode(code.slice(0, -1) + (code.endsWith('0') ? '1' : '0'))).toBeNull();
  });
  it('generates unique serials', () => {
    expect(new Set(Array.from({ length: 2000 }, c.newSerial)).size).toBe(2000);
  });
});

describe('PII encryption (RA 10173)', () => {
  it('round-trips and never stores plaintext', () => {
    const enc = c.encryptPII('+639171234567');
    expect(enc.toString('utf8')).not.toContain('639171234567');
    expect(c.decryptPII(enc)).toBe('+639171234567');
  });
  it('detects tampering', () => {
    const enc = c.encryptPII('+639171234567');
    enc[enc.length - 1] ^= 1;
    expect(() => c.decryptPII(enc)).toThrow();
  });
});
