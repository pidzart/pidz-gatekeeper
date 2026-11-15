// Poseidon hashing via circomlibjs — the same implementation family the
// vfy-policy circuit template uses (circomlib Poseidon over the BN128 field).
//
// Used for exactly two things in Steal the VFY:
//   commitment = Poseidon9([strategyParams[0..7], salt])
//   proofTag   = Poseidon3([matchId, turnNumber, circuitVersion])  (circuit output)
import { buildPoseidon } from 'circomlibjs';

export const BN128_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

let poseidonPromise = null;

async function getPoseidon() {
  if (!poseidonPromise) poseidonPromise = buildPoseidon();
  return poseidonPromise;
}

/** Poseidon over 1..16 field elements → BigInt. Throws on out-of-field input. */
export async function poseidonHash(inputs) {
  const values = inputs.map((v) => BigInt(v));
  if (values.length < 1 || values.length > 16) {
    throw new Error(`Poseidon needs 1..16 inputs in one call, got ${values.length}`);
  }
  for (const v of values) {
    if (v < 0n || v >= BN128_PRIME) {
      throw new Error(`Poseidon input is not a BN128 field element: ${v}`);
    }
  }
  const poseidon = await getPoseidon();
  return BigInt(poseidon.F.toString(poseidon(values)));
}

/** commitment = Poseidon9(strategyParams[0..7], salt) → BigInt. */
export async function computeCommitment(params, salt) {
  if (!Array.isArray(params) || params.length !== 8) {
    throw new Error('computeCommitment needs exactly 8 strategy params');
  }
  return poseidonHash([...params.map((p) => BigInt(p)), BigInt(salt)]);
}

/** Commitment as the on-wire form used by the envelope: 0x + 64 lowercase hex. */
export async function computeCommitmentHex(params, salt) {
  const c = await computeCommitment(params, salt);
  return '0x' + c.toString(16).padStart(64, '0');
}

/** proofTag = Poseidon3(matchId, turnNumber, circuitVersion) → BigInt. */
export async function computeProofTag(matchIdField, turnNumber, circuitVersion) {
  return poseidonHash([BigInt(matchIdField), BigInt(turnNumber), BigInt(circuitVersion)]);
}
