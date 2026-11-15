// Strategy for Steal the VFY — a faithful mirror of the vfy-policy circuit.
//
// IMPORTANT DESIGN FACT (recovered circuit source, see FINDINGS.md): the
// circuit does NOT prove an arbitrary per-turn decision. It proves that the
// submitted action is the UNIQUE output of one fixed parameterized policy:
//
//   if selfBalance < params[1] (fortifyThreshold)        -> FORTIFY
//   elif opponentBalance > params[2] (extractThreshold)
//        AND params[3] (holdPriority) == 0               -> EXTRACT params[0]
//   else                                                 -> HOLD
//
// with amount == params[0] exactly for EXTRACT and 0 otherwise. Any action
// that deviates from this rule for the committed params makes fullProve throw
// — there is no way to attach a valid proof to a different move. So the
// "strategy" of this track IS the choice of (strategyParams, salt); the
// per-turn decision below is deterministic and must match the circuit bit for
// bit. In particular, "FORTIFY when ahead" is NOT expressible: the circuit
// fortifies when your balance is LOW (defensive), never when it is high.

/** Circuit action codes (vfy-policy.circom: 0 = HOLD, 1 = FORTIFY, 2 = EXTRACT). */
export const ACTION_CODE = { HOLD: 0, FORTIFY: 1, EXTRACT: 2 };
export const ACTION_NAME = ['HOLD', 'FORTIFY', 'EXTRACT'];

/** Resolver constants (platform-side, not circuit-enforced). */
export const EXTRACT_CAP = 10; // hard upper bound on params[0]
export const FORTIFY_COST = 2; // VFY paid when FORTIFY resolves
export const FORTIFY_BLOCK = 6; // max incoming extraction blocked by FORTIFY

/**
 * Default committed policy: [10, 30, 0, 0, 0, 0, 0, 0]
 *  - EXTRACT the maximum 10 whenever the opponent holds anything: the
 *    resolver caps the actual transfer at the opponent's exposed balance, so
 *    a smaller request only leaves VFY on the table; against a fortified
 *    opponent 10 - 6 = 4 still lands, while e.g. 5 - 6 lands nothing.
 *  - FORTIFY only when badly weakened (self < 30): it costs 2 to block at
 *    most 6, which pays only when a full 10-extraction is likely and the
 *    balance swing matters; above 30, extracting dominates.
 */
export const DEFAULT_PARAMS = [10, 30, 0, 0, 0, 0, 0, 0];

/**
 * Conservative alternative profile: [5, 40, 20, 0, 0, 0, 0, 0]
 * Smaller extractions, earlier defence, and no extraction against an
 * opponent at or below 20. Weaker in expectation (see FINDINGS.md) but kept
 * as a documented option.
 */
export const CONSERVATIVE_PARAMS = [5, 40, 20, 0, 0, 0, 0, 0];

const MAX_U16 = 65535; // circuit comparators are 16-bit (VfyPolicyProof(16, 10))

/**
 * Validate strategy params against the circuit's constraints.
 * Returns a copy of the 8 numbers; throws an Error naming the failed rule.
 */
export function validateStrategyParams(params) {
  if (!Array.isArray(params) || params.length !== 8) {
    throw new Error(`strategyParams must be an array of exactly 8 integers, got: ${JSON.stringify(params)}`);
  }
  const p = params.map((v) => {
    const n = typeof v === 'bigint' ? Number(v) : v;
    if (typeof n !== 'number' || !Number.isInteger(n)) {
      throw new Error(`strategyParams entries must be integers, got: ${JSON.stringify(v)}`);
    }
    return n;
  });
  if (p[0] < 1 || p[0] > EXTRACT_CAP) {
    throw new Error(
      `strategyParams[0] (extractAmount) must be in [1, ${EXTRACT_CAP}], got ${p[0]}. ` +
        'Note: params[0] = 0 can NEVER prove — the circuit range assert rejects it.',
    );
  }
  if (p[1] < 0 || p[1] > MAX_U16) {
    throw new Error(`strategyParams[1] (fortifyThreshold) must be in [0, ${MAX_U16}], got ${p[1]}`);
  }
  if (p[2] < 0 || p[2] > MAX_U16) {
    throw new Error(`strategyParams[2] (extractThreshold) must be in [0, ${MAX_U16}], got ${p[2]}`);
  }
  if (p[3] !== 0 && p[3] !== 1) {
    throw new Error(`strategyParams[3] (holdPriority) must be 0 or 1, got ${p[3]}`);
  }
  for (let i = 4; i < 8; i++) {
    if (p[i] !== 0) {
      throw new Error(`strategyParams[${i}] is reserved and must be exactly 0, got ${p[i]}`);
    }
  }
  return p;
}

/** Parse a salt given as a decimal string, a 0x-hex string, a number or a BigInt. */
export function parseSalt(salt) {
  if (typeof salt === 'bigint') {
    if (salt < 0n) throw new Error('salt must be non-negative');
    return salt;
  }
  if (typeof salt === 'number') {
    if (!Number.isSafeInteger(salt) || salt < 0) throw new Error(`salt is not a safe non-negative integer: ${salt}`);
    return BigInt(salt);
  }
  const s = String(salt).trim();
  if (s === '') throw new Error('salt is empty');
  const v = BigInt(s); // accepts decimal and 0x-prefixed hex
  if (v < 0n) throw new Error('salt must be non-negative');
  return v;
}

/**
 * The deterministic policy decision — must mirror the circuit exactly.
 * state: { selfBalance, opponentBalance } (numbers, numeric strings or BigInts).
 * Returns { type: 'HOLD'|'FORTIFY' } or { type: 'EXTRACT', amount }.
 * The returned object intentionally OMITS `amount` for HOLD/FORTIFY: the
 * response schema rejects the field even when it is 0.
 */
export function decideAction(state, params) {
  const p = validateStrategyParams(params);
  const self = BigInt(state.selfBalance);
  const opp = BigInt(state.opponentBalance);
  if (self < 0n || opp < 0n) throw new Error('balances must be non-negative');

  if (self < BigInt(p[1])) return { type: 'FORTIFY' };
  if (opp > BigInt(p[2]) && p[3] === 0) return { type: 'EXTRACT', amount: p[0] };
  return { type: 'HOLD' };
}

/** Amount as the circuit sees it: params[0] for EXTRACT, 0 for anything else. */
export function circuitAmount(action, params) {
  return action.type === 'EXTRACT' ? validateStrategyParams(params)[0] : 0;
}
