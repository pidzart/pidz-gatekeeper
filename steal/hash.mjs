// publicInputsHash + matchId conversion for Steal the VFY.
//
// Recipe (official /build §06, confirmed identically by four independent
// participant implementations — see FINDINGS.md):
//   keccak256 of eight 32-byte big-endian uint256 words, in this exact order:
//     1. strategy commitment hash (as integer)
//     2. matchId: UUID with hyphens removed, parsed as a hexadecimal integer
//     3. turn
//     4. selfBalance
//     5. opponentBalance
//     6. action code: HOLD = 0, FORTIFY = 1, EXTRACT = 2
//     7. amount (0 for HOLD / FORTIFY)
//     8. circuitVersion "v1" encoded as integer 1
// This is Keccak-256 (NOT SHA3-256), over raw ABI words — not a field element,
// not Poseidon, and it does NOT include the circuit's proofTag output.
import jsSha3 from 'js-sha3';
import { ACTION_CODE } from './strategy.mjs';

const { keccak256 } = jsSha3;

const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/** matchId UUID string -> the uint128 field/word value used everywhere. */
export function matchIdToBigInt(matchId) {
    const compact = String(matchId).trim().replace(/-/g, '').toLowerCase();
    if (!/^[0-9a-f]{32}$/.test(compact)) {
          throw new Error(`matchId is not a 32-hex-digit UUID: ${JSON.stringify(matchId)}`);
    }
    return BigInt('0x' + compact);
}

export function isUuid(s) {
    return typeof s === 'string' && UUID_RE.test(s);
}

/** "v1" -> 1n. Throws on anything else. */
export function circuitVersionToBigInt(version) {
    const m = /^v(\d+)$/.exec(String(version).trim());
    if (!m) throw new Error(`invalid circuitVersion: ${JSON.stringify(version)} (expected e.g. "v1")`);
    return BigInt(m[1]);
}

function word32(value) {
    const v = BigInt(value);
    if (v < 0n || v >= 1n << 256n) throw new Error(`value does not fit in uint256: ${v}`);
    const hex = v.toString(16).padStart(64, '0');
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return bytes;
}

/** Keccak256 over an array of uint256-sized values, each encoded as a 32-byte BE word. */
export function publicInputsHashFromWords(words) {
    if (!Array.isArray(words) || words.length !== 8) {
          throw new Error(`publicInputsHash needs exactly 8 words, got ${words && words.length}`);
    }
    const buf = new Uint8Array(8 * 32);
    words.forEach((w, i) => buf.set(word32(w), i * 32));
    return '0x' + keccak256(buf);
}

/**
 * Compute the publicInputsHash for one turn.
 * input: {
 *   commitment: hex string ("0x...") or BigInt — the registered commitment,
 *   matchId: UUID string,
 *   turn, selfBalance, opponentBalance,
 *   action: 'HOLD'|'FORTIFY'|'EXTRACT' (or a {type, amount} action object),
 *   amount: number (ignored unless action is EXTRACT; defaults from action obj),
 *   circuitVersion: 'v1'
 * }
 */
export function publicInputsHash(input) {
    const actionObj = typeof input.action === 'object' && input.action !== null ? input.action : null;
    const actionType = actionObj ? actionObj.type : input.action;
    if (!(actionType in ACTION_CODE)) throw new Error(`unknown action: ${JSON.stringify(input.action)}`);
    const amount = actionType === 'EXTRACT' ? BigInt(input.amount ?? actionObj?.amount ?? 0) : 0n;
    const commitment =
          typeof input.commitment === 'string' ? BigInt(input.commitment) : BigInt(input.commitment);
    return publicInputsHashFromWords([
          commitment,
          matchIdToBigInt(input.matchId),
          BigInt(input.turn),
          BigInt(input.selfBalance),
          BigInt(input.opponentBalance),
          BigInt(ACTION_CODE[actionType]),
          amount,
          circuitVersionToBigInt(input.circuitVersion ?? 'v1'),
        ]);
}
