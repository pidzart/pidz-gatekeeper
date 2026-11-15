# pidz-gatekeeper

An autonomous agent for **zkVerify Agent Games Season 01** (@pidz-ai), competing in
**Proof Gatekeeper** and **Steal the VFY**, with a Wildcard entry on the same agent.

**Proofs, not promises.** The agent never asks to be trusted: every decision it
issues is backed by a Groth16 zero-knowledge proof, generated locally and
self-verified against the official circuit verification key before it is sent.

## Proof Gatekeeper (`src/`)

The agent judges payment conditions — registered verification key, minimum
balance, expiry block, intended recipient, maximum amount — and answers
APPROVE or REJECT. It fail-closes on six traps, each with a machine-readable
reason code:

1. verification-key substitution
2. proof replay (`proof_tx` reuse)
3. threshold mismatch
4. expired conditions
5. recipient mismatch
6. amount overflow

Requests and responses are HMAC-SHA256 signed over the raw body. Decisions are
deterministic; the Groth16 proof (official `gatekeeper` circuit, snarkjs) binds
each decision to its exact task. Task responses are cached by `task_id` for
idempotent redelivery. Platform record: signed preflight passed, practice task
scored CORRECT with the proof VERIFIED by the platform (~1.7s end to end).

## Steal the VFY (`steal/`)

A policy agent for the 1v1 VFY duel (20 turns, Swiss rounds). Its whole
strategy is committed up front as a Poseidon hash of 8 strategy parameters +
salt, and every turn answer carries a Groth16 proof (official `vfy-policy`
circuit) that the move follows the committed policy:

- `HOLD = 0`, `FORTIFY = 1`, `EXTRACT = 2`
- EXTRACT amount is the circuit-enforced parameter (cap 10); the platform
  resolver caps the effective transfer at the opponent's exposed balance, so
  requesting the maximum is never worse than requesting less
- FORTIFY triggers only below a balance threshold (it costs 2 VFY to block up
  to 6)

`steal/FINDINGS.md` documents the full protocol reconstruction — envelope
schema, action encoding, commitment function (`Poseidon9(params, salt)`),
`publicInputsHash` recipe (Keccak-256 over 8 big-endian words) — cross-checked
against the recovered circuit source and three independent participant
implementations, with golden test vectors verified bit-for-bit. Local test
suite: 12/12 checks pass, including `fullProve` + `groth16.verify` against the
official verification key for EXTRACT, FORTIFY and HOLD turns.

Fail-closed throughout: any validation failure, commitment mismatch or proof
error degrades to a HOLD answer without a proof claim — an invalid proof costs
points, an unproven HOLD does not.

## Layout

- `src/` — Proof Gatekeeper agent (HTTP server, handler, decision engine, prover)
- `steal/` — Steal the VFY policy module (strategy, Poseidon commitment, turn handler)
- Circuit artifacts are the official ones published by the Agent Games
  platform and are not redistributed here.

## Not in this repo

Secrets by design: the HMAC secret and the Steal strategy salt live only in
local, permission-locked config on the agent host (`agent.env`,
`strategy.local.json`, both git-ignored). The strategy commitment hash itself
is public — it is registered on the Agent Games dashboard.
