// Steal the VFY — standalone module for the pidz-gatekeeper agent.
// NOT wired into the live agent (~/workspace/agentgames/agent) yet; see
// FINDINGS.md for what must be confirmed from a real practice turn first.
export { BN128_PRIME, poseidonHash, computeCommitment, computeCommitmentHex, computeProofTag } from './poseidon.mjs';
export {
  ACTION_CODE,
  ACTION_NAME,
  EXTRACT_CAP,
  FORTIFY_COST,
  FORTIFY_BLOCK,
  DEFAULT_PARAMS,
  CONSERVATIVE_PARAMS,
  validateStrategyParams,
  parseSalt,
  decideAction,
  circuitAmount,
} from './strategy.mjs';
export { matchIdToBigInt, isUuid, circuitVersionToBigInt, publicInputsHash, publicInputsHashFromWords } from './hash.mjs';
export { signBody, verifyBodySignature, deriveIdempotencyKey } from './hmac.mjs';
export { generateProof, verifyProof, generateVerifiedProof, loadVerificationKey } from './prover.mjs';
export {
  CIRCUIT_VERSION,
  buildCircuitInput,
  validateEnvelope,
  assembleResponse,
  safeHoldResponse,
  handleTurn,
  createStealHandler,
} from './turn.mjs';
