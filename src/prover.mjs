import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as snarkjs from 'snarkjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const CIRCUITS_DIR = process.env.CIRCUITS_DIR || path.resolve(here, '../../circuits');
const WASM = path.join(CIRCUITS_DIR, 'gatekeeper.wasm');
const ZKEY = path.join(CIRCUITS_DIR, 'gatekeeper_final.zkey');

export async function generateProof(circuitInput) {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, WASM, ZKEY);
  return { proof, publicSignals };
}
