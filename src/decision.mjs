import crypto from 'node:crypto';
import { BN128_PRIME } from './hmac.mjs';

const normAddr = (a) => String(a || '').toLowerCase();
const normHash = (h) => String(h || '').toLowerCase();

// Deterministic policy. APPROVE only when every check passes; otherwise the
// first failing check (in the order below) names the reason code. Trap tasks
// are single-fault by design, so ordering rarely decides between two codes.
export function decide(input, isProofTxSeen) {
  if (normHash(input.proof_vk) !== normHash(input.registered_vk)) {
    return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };
  }
  if (isProofTxSeen) {
    return { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
  }
  if (BigInt(input.public_balance) < BigInt(input.minimum)) {
    return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
  }
  if (!(BigInt(input.current_block) < BigInt(input.expiry_block))) {
    return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' };
  }
  if (normAddr(input.recipient) !== normAddr(input.condition_recipient)) {
    return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
  }
  if (BigInt(input.amount) > BigInt(input.max_transfer)) {
    return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW' };
  }
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
}

function fieldFromBigIntString(value) {
  // value may be a decimal string, a 0x-hex string, or a JS number
  let b;
  if (typeof value === 'number') b = BigInt(value);
  else if (typeof value === 'string' && /^0x[0-9a-fA-F]+$/.test(value.trim())) b = BigInt(value.trim());
  else b = BigInt(String(value).trim());
  return (b % BN128_PRIME).toString();
}

export function taskIdToField(taskId) {
  const s = String(taskId);
  if (/^0x[0-9a-fA-F]+$/.test(s)) return (BigInt(s) % BN128_PRIME).toString();
  if (/^\d+$/.test(s)) return (BigInt(s) % BN128_PRIME).toString();
  const digest = crypto.createHash('sha256').update(s).digest();
  return (BigInt('0x' + digest.toString('hex')) % BN128_PRIME).toString();
}

// Build the gatekeeper circuit input. `decisionBit` is 1 for APPROVE, 0 for
// REJECT; the circuit itself asserts decision == AND(all field checks), so a
// wrong decision cannot produce a witness.
export function buildCircuitInput(task, input, decisionBit, salt) {
  return {
    taskId: taskIdToField(task.task_id),
    registeredVkHash: fieldFromBigIntString(input.registered_vk),
    proofVkHash: fieldFromBigIntString(input.proof_vk),
    minimum: fieldFromBigIntString(input.minimum),
    publicBalance: fieldFromBigIntString(input.public_balance),
    expiryBlock: fieldFromBigIntString(input.expiry_block),
    currentBlock: fieldFromBigIntString(input.current_block),
    recipient: fieldFromBigIntString(input.recipient),
    conditionRecipient: fieldFromBigIntString(input.condition_recipient),
    amount: fieldFromBigIntString(input.amount),
    maxTransfer: fieldFromBigIntString(input.max_transfer),
    decision: String(decisionBit),
    salt: salt.toString(),
  };
}
