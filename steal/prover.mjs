// Groth16 proving for the official vfy-policy circuit, mirroring the live
// Gatekeeper agent's prover (snarkjs fullProve against the pinned artifacts
// in ../../circuits). Adds local verification against the official VK so a
// response never carries a proof we have not checked ourselves.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as snarkjs from 'snarkjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const CIRCUITS_DIR = process.env.CIRCUITS_DIR || path.resolve(here, '../../circuits');
const WASM = path.join(CIRCUITS_DIR, 'vfy-policy.wasm');
const ZKEY = path.join(CIRCUITS_DIR, 'vfy-policy_final.zkey');
const VK_PATH = path.join(CIRCUITS_DIR, 'vfy-policy_verification_key.json');

let vkCache = null;
export function loadVerificationKey() {
  if (!vkCache) vkCache = JSON.parse(fs.readFileSync(VK_PATH, 'utf8'));
  return vkCache;
}

export async function generateProof(circuitInput) {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, WASM, ZKEY);
  return { proof, publicSignals };
}

/** Local groth16.verify against the official verification key. */
export async function verifyProof(proof, publicSignals) {
  return snarkjs.groth16.verify(loadVerificationKey(), publicSignals, proof);
}

/** Generate a proof and self-verify it; throws if verification fails. */
export async function generateVerifiedProof(circuitInput) {
  const { proof, publicSignals } = await generateProof(circuitInput);
  const ok = await verifyProof(proof, publicSignals);
  if (!ok) throw new Error('local groth16.verify failed for a freshly generated proof');
  return { proof, publicSignals };
}
