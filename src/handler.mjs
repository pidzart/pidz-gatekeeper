import { signBody, verifyBodySignature, deriveSalt } from './hmac.mjs';
import { decide, buildCircuitInput } from './decision.mjs';
import { generateProof } from './prover.mjs';

const REQUIRED_INPUT_FIELDS = [
  'registered_vk', 'proof_vk', 'minimum', 'public_balance', 'expiry_block',
  'current_block', 'recipient', 'condition_recipient', 'amount',
  'max_transfer', 'proof_tx',
];

export function createHandler({ secret, store, log = console }) {
  function signedJson(status, obj) {
    const body = JSON.stringify(obj);
    const headers = { 'content-type': 'application/json' };
    if (secret) headers['x-agent-games-signature'] = signBody(secret, body);
    return { status, headers, body };
  }

  async function handleGatekeeper(task) {
    const taskId = task.task_id;

    // Idempotent redelivery: same task_id returns the identical response.
    const cached = store.getCached(taskId);
    if (cached) {
      const headers = { 'content-type': 'application/json' };
      if (secret) headers['x-agent-games-signature'] = signBody(secret, cached);
      return { status: 200, headers, body: cached };
    }

    const input = task.input || {};
    const missing = REQUIRED_INPUT_FIELDS.filter((f) => input[f] === undefined || input[f] === null || input[f] === '');
    if (missing.length) {
      // Envelope-level failure, off the scored paths: fail closed, no proof.
      const res = signedJson(200, {
        decision: 'REJECT', reason_code: 'INVALID_TASK', proof_tx: input.proof_tx ?? null,
      });
      store.setCached(taskId, res.body);
      store.flush();
      return res;
    }

    const seen = store.hasSeenProofTx(input.proof_tx);
    const { decision, reason_code } = decide(input, seen);
    const decisionBit = decision === 'APPROVE' ? 1 : 0;

    const payload = { decision, reason_code, proof_tx: input.proof_tx };

    // PROOF_REUSED carries no proof: the circuit cannot prove decision=0 for
    // an otherwise-valid statement, and the event rules exclude it from
    // proof scoring.
    if (reason_code !== 'PROOF_REUSED') {
      try {
        const circuitInput = buildCircuitInput(task, input, decisionBit, deriveSalt(secret, taskId));
        const { proof, publicSignals } = await generateProof(circuitInput);
        payload.proof = proof;
        payload.public_signals = publicSignals;
      } catch (err) {
        // Fail closed: keep the deterministic decision, omit the proof.
        log.error(`[agent] proof generation failed for ${taskId}: ${err.message}`);
      }
    }

    const res = signedJson(200, payload);
    store.markSeenProofTx(input.proof_tx, taskId);
    store.setCached(taskId, res.body);
    store.flush();
    return res;
  }

  // Returns { status, headers, body } for a POST with the given raw body.
  async function handlePost(rawBody, signatureHeader) {
    if (secret && !verifyBodySignature(secret, rawBody, signatureHeader)) {
      return {
        status: 401,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ error: 'invalid signature' }),
      };
    }

    let task;
    try {
      task = JSON.parse(rawBody.toString('utf8'));
    } catch {
      return {
        status: 400,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ error: 'invalid json' }),
      };
    }

    if (task.type === 'agent-games.preflight.v1') {
      return signedJson(200, { ok: true, protocolVersion: 'v1' });
    }

    if (task.type === 'agent-games.proof-gatekeeper.v1') {
      return handleGatekeeper(task);
    }

    return signedJson(400, { error: 'unknown task type' });
  }

  return { handlePost, signedJson };
}
