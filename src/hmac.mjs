import crypto from 'node:crypto';

export const BN128_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// HMAC-SHA256, key = secret string (UTF-8), digest hex — the platform convention.
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

// Accept the same MAC bytes in hex or base64 form; constant-time compare.
export function verifyBodySignature(secret, rawBody, headerValue) {
  const candidate = decodeCandidate(headerValue);
  if (!candidate) return false;
  const expected = macBytes(secret, rawBody);
  return candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected);
}

// Deterministic per-task private salt for the circuit: same task_id + secret
// always reproduces the same proof inputs (safe under platform redelivery).
export function deriveSalt(secret, taskId) {
  const digest = crypto
    .createHmac('sha256', secret || 'gatekeeper-local-dev')
    .update(`gatekeeper-salt:${taskId}`)
    .digest();
  return BigInt('0x' + digest.toString('hex')) % BN128_PRIME;
}
