// Turn handling for Steal the VFY: envelope -> decision -> circuit input ->
// proof -> signed response. Mirrors the live Gatekeeper handler's shape
// (createHandler / handlePost / signedJson) so integration later is a
// drop-in branch, but this module is STANDALONE — nothing here is wired
// into the running agent.
//
// Fail-closed rule (platform semantics): any error, mismatch or expired
// deadline degrades to a HOLD response WITHOUT a proof claim, never to a
// guessed action. A missing/invalid response is scored by the platform as
// HOLD anyway; a wrong proof costs -2, so an unproven HOLD is the safe floor.
import { signBody, verifyBodySignature, deriveIdempotencyKey } from './hmac.mjs';
import {
  ACTION_CODE,
  circuitAmount,
  decideAction,
  parseSalt,
  validateStrategyParams,
} from './strategy.mjs';
import { computeCommitment } from './poseidon.mjs';
import { matchIdToBigInt, publicInputsHash } from './hash.mjs';
import { generateVerifiedProof } from './prover.mjs';

export const CIRCUIT_VERSION = 'v1';
export const CIRCUIT_VERSION_NUMBER = 1;

/**
 * Build the 17-element vfy-policy circuit input (9 scalars + strategyParams[8])
 * as decimal strings, the format snarkjs fullProve accepts.
 * `commitment` is a BigInt (the registered commitment for params+salt).
 */
export function buildCircuitInput(envelope, action, { params, salt, commitment }) {
  const p = validateStrategyParams(params);
  return {
    commitment: BigInt(commitment).toString(),
    matchId: matchIdToBigInt(envelope.matchId).toString(),
    turnNumber: String(envelope.turn),
    selfBalance: BigInt(envelope.state.selfBalance).toString(),
    opponentBalance: BigInt(envelope.state.opponentBalance).toString(),
    action: String(ACTION_CODE[action.type]),
    amount: String(circuitAmount(action, p)),
    circuitVersion: String(CIRCUIT_VERSION_NUMBER),
    strategyParams: p.map((v) => String(v)),
    salt: parseSalt(salt).toString(),
  };
}

/** Structural validation of a turn envelope. Returns an error string or null. */
export function validateEnvelope(envelope) {
  if (!envelope || typeof envelope !== 'object') return 'envelope is not an object';
  if (envelope.eventId !== undefined && envelope.eventId !== 'steal-the-vfy') {
    return `unexpected eventId: ${envelope.eventId}`;
  }
  if (typeof envelope.matchId !== 'string' || envelope.matchId === '') return 'missing matchId';
  if (!Number.isInteger(envelope.turn) || envelope.turn < 1 || envelope.turn > 20) {
    return `turn out of range: ${envelope.turn}`;
  }
  if (!envelope.state || typeof envelope.state !== 'object') return 'missing state';
  for (const f of ['selfBalance', 'opponentBalance']) {
    const v = envelope.state[f];
    if (v === undefined || v === null || !/^\d+$/.test(String(v))) return `state.${f} is not a non-negative integer: ${v}`;
    if (BigInt(v) > 65535n) return `state.${f} exceeds the circuit's 16-bit comparator domain: ${v}`;
  }
  // strategyCommitment is OPTIONAL: the real practice envelope observed
  // 2026-11-15 omits it entirely (competition envelopes are expected to
  // carry it). When present it must be a 32-byte hex string; when absent we
  // prove against our own registered commitment.
  if (envelope.strategyCommitment !== undefined && envelope.strategyCommitment !== null) {
    if (typeof envelope.strategyCommitment.hash !== 'string') {
      return 'strategyCommitment.hash is not a string';
    }
    if (!/^0x[0-9a-fA-F]{64}$/.test(envelope.strategyCommitment.hash)) {
      return 'strategyCommitment.hash is not a 32-byte hex string';
    }
  }
  return null;
}

function isExpired(envelope, marginMs = 2000) {
  if (!envelope.deadlineAt) return false;
  const deadline = Date.parse(envelope.deadlineAt);
  if (Number.isNaN(deadline)) return false;
  return Date.now() > deadline - marginMs;
}

/**
 * Assemble the response object for an action, optionally with proof material.
 *
 * PROOF PLACEMENT (see FINDINGS.md §1): participant implementations diverge —
 * some put `proof`/`public_signals` at the top level, others nest
 * `proof`/`publicSignals` inside `policyProof`. The build guide describes the
 * policy proof as one bundle ("circuitVersion plus the Groth16 proof and
 * public_signals"). Default here is 'both': identical proof material in both
 * places, so a missing-field rejection (scored as HOLD) cannot happen on
 * placement grounds. Switch with config.proofPlacement once the real practice
 * turn shows which shape the platform accepts.
 */
export function assembleResponse(envelope, action, { hash, proof, publicSignals, proofPlacement = 'both' } = {}) {
  const policyProof = { circuitVersion: CIRCUIT_VERSION };
  if (hash) policyProof.publicInputsHash = hash;
  const response = {
    protocolVersion: 'v1',
    matchId: envelope.matchId,
    turn: envelope.turn,
    action,
    policyProof,
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: envelope.idempotencyKey || deriveIdempotencyKey(envelope.matchId, envelope.turn),
  };
  if (proof && publicSignals) {
    if (proofPlacement === 'both' || proofPlacement === 'policyProof') {
      policyProof.proof = proof;
      policyProof.publicSignals = publicSignals;
      policyProof.public_signals = publicSignals;
    }
    if (proofPlacement === 'both' || proofPlacement === 'topLevel') {
      response.proof = proof;
      response.public_signals = publicSignals;
    }
  }
  return response;
}

/** HOLD fallback with the correct HOLD publicInputsHash when computable. */
export function safeHoldResponse(envelope, commitmentHex) {
  let hash;
  try {
    hash = publicInputsHash({
      commitment: commitmentHex ?? envelope.strategyCommitment.hash,
      matchId: envelope.matchId,
      turn: envelope.turn,
      selfBalance: envelope.state.selfBalance,
      opponentBalance: envelope.state.opponentBalance,
      action: 'HOLD',
      circuitVersion: CIRCUIT_VERSION,
    });
  } catch { /* envelope too broken to hash — policyProof stays minimal */ }
  return assembleResponse(envelope, { type: 'HOLD' }, { hash });
}

/**
 * Handle one parsed turn envelope.
 * config: { params, salt, commitmentHex?, proofPlacement?, log? }
 * Returns { response, proofStatus, reason } — never throws for a bad turn.
 */
export async function handleTurn(envelope, config) {
  const log = config.log || console;
  const params = validateStrategyParams(config.params);
  const salt = parseSalt(config.salt);
  const commitment = await computeCommitment(params, salt);
  const commitmentHex = '0x' + commitment.toString(16).padStart(64, '0');
  if (config.commitmentHex && config.commitmentHex.toLowerCase() !== commitmentHex) {
    throw new Error('config.commitmentHex does not match Poseidon(params, salt) — refusing to run a mismatched strategy');
  }

  const invalid = validateEnvelope(envelope);
  if (invalid) {
    return { response: safeHoldResponse(envelope, commitmentHex), proofStatus: 'no-proof', reason: `invalid envelope (${invalid}) -> HOLD` };
  }

  // The envelope's frozen commitment must be ours; a mismatch means this
  // agent is not the paired one for this match (or the config is wrong).
  // An ABSENT commitment (practice mode) is fine: prove against our own.
  if (envelope.strategyCommitment?.hash && envelope.strategyCommitment.hash.toLowerCase() !== commitmentHex) {
    return {
      response: safeHoldResponse(envelope, commitmentHex),
      proofStatus: 'no-proof',
      reason: `strategyCommitment.hash mismatch (envelope ${envelope.strategyCommitment.hash} != ours ${commitmentHex}) -> HOLD`,
    };
  }

  if (isExpired(envelope)) {
    return { response: safeHoldResponse(envelope, commitmentHex), proofStatus: 'no-proof', reason: 'deadlineAt already passed -> HOLD' };
  }

  const action = decideAction(envelope.state, params);
  const hash = publicInputsHash({
    commitment: commitmentHex,
    matchId: envelope.matchId,
    turn: envelope.turn,
    selfBalance: envelope.state.selfBalance,
    opponentBalance: envelope.state.opponentBalance,
    action,
    circuitVersion: CIRCUIT_VERSION,
  });

  try {
    const circuitInput = buildCircuitInput(envelope, action, { params, salt, commitment });
    const { proof, publicSignals } = await generateVerifiedProof(circuitInput);
    return {
      response: assembleResponse(envelope, action, {
        hash,
        proof,
        publicSignals,
        proofPlacement: config.proofPlacement,
      }),
      proofStatus: 'proved',
      reason: `proof generated and locally verified (${action.type})`,
    };
  } catch (err) {
    log.error(`[steal] proof generation failed for ${envelope.matchId} turn ${envelope.turn}: ${err.message}`);
    return {
      response: assembleResponse(envelope, { type: 'HOLD' }, { hash: publicInputsHash({
        commitment: commitmentHex,
        matchId: envelope.matchId,
        turn: envelope.turn,
        selfBalance: envelope.state.selfBalance,
        opponentBalance: envelope.state.opponentBalance,
        action: 'HOLD',
        circuitVersion: CIRCUIT_VERSION,
      }) }),
      proofStatus: 'proof-error',
      reason: `proof failed (${err.message}) -> HOLD without proof`,
    };
  }
}

/**
 * HTTP-level handler with the same contract as the Gatekeeper agent's
 * handlePost: (rawBody, signatureHeader) -> { status, headers, body }.
 * Dispatches preflight and steal-the-vfy turn envelopes; responses are
 * HMAC-signed over the raw response body when a secret is configured.
 * config: { secret, params, salt, commitmentHex?, proofPlacement?, log? }
 */
export function createStealHandler(config) {
  const cache = new Map(); // idempotencyKey -> response body string

  function signedJson(status, obj) {
    const body = JSON.stringify(obj);
    const headers = { 'content-type': 'application/json' };
    if (config.secret) headers['x-agent-games-signature'] = signBody(config.secret, body);
    return { status, headers, body };
  }

  async function handlePost(rawBody, signatureHeader) {
    if (config.secret && !verifyBodySignature(config.secret, rawBody, signatureHeader)) {
      return {
        status: 401,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ error: 'invalid signature' }),
      };
    }

    let envelope;
    try {
      envelope = JSON.parse(rawBody.toString('utf8'));
    } catch {
      return { status: 400, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ error: 'invalid json' }) };
    }

    if (envelope.type === 'agent-games.preflight.v1') {
      return signedJson(200, { ok: true, protocolVersion: 'v1' });
    }

    if (envelope.eventId === 'steal-the-vfy' || envelope.state) {
      const key = envelope.idempotencyKey || deriveIdempotencyKey(String(envelope.matchId || ''), envelope.turn ?? 0);
      const cached = cache.get(key);
      if (cached) {
        const headers = { 'content-type': 'application/json' };
        if (config.secret) headers['x-agent-games-signature'] = signBody(config.secret, cached);
        return { status: 200, headers, body: cached };
      }
      const { response } = await handleTurn(envelope, config);
      const res = signedJson(200, response);
      cache.set(key, res.body);
      if (cache.size > 1000) cache.delete(cache.keys().next().value);
      return res;
    }

    return signedJson(400, { error: 'unknown task type' });
  }

  return { handlePost, signedJson };
}
