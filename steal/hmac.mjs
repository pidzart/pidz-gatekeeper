// HMAC-SHA256 over the raw body — the shared Agent Games platform scheme,
// identical to the live Proof Gatekeeper agent (see ../../agent/src/hmac.mjs).
// Key = the platform-issued secret string (UTF-8); digest carried in the
// `x-agent-games-signature` header as hex (base64 also accepted inbound).
import crypto from 'node:crypto';

export function signBody(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}

function macBytes(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest();
}

function decodeCandidate(headerValue) {
  if (!headerValue || typeof headerValue !== 'string') return null;
  let v = headerValue.trim();
  if (v.toLowerCase().startsWith('sha256=')) v = v.slice('sha256='.length).trim();
  if (/^[0-9a-fA-F]{64}$/.test(v)) return Buffer.from(v, 'hex');
  try {
    const b = Buffer.from(v, 'base64');
    if (b.length === 32) return b;
  } catch { /* fall through */ }
  return null;
}

export function verifyBodySignature(secret, rawBody, headerValue) {
  const candidate = decodeCandidate(headerValue);
  if (!candidate) return false;
  const expected = macBytes(secret, rawBody);
  return candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected);
}

/**
 * Deterministic per-turn idempotency key: UUIDv5-style formatting of
 * SHA-256("steal:<matchId>:<turn>"). A platform retry of the same turn
 * derives the same key (and the handler returns the cached response); a
 * different turn never collides. If the platform sends its own
 * idempotencyKey in the envelope, that one wins.
 */
export function deriveIdempotencyKey(matchId, turn) {
  const digest = crypto.createHash('sha256').update(`steal:${matchId}:${turn}`, 'utf8').digest();
  digest[6] = (digest[6] & 0x0f) | 0x50;
  digest[8] = (digest[8] & 0x3f) | 0x80;
  const hex = digest.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}
