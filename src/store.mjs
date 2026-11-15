import fs from 'node:fs';
import path from 'node:path';

// File-backed seen-set (proof_tx -> task_id) + idempotency cache
// (task_id -> raw response body). Small scale (8 tasks/round), sync writes OK.
export class Store {
  constructor(filePath) {
    this.filePath = filePath;
    this.seen = new Map();
    this.cache = new Map();
    try {
      const raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      this.seen = new Map(Object.entries(raw.seen || {}));
      this.cache = new Map(Object.entries(raw.cache || {}));
    } catch { /* fresh store */ }
  }

  flush() {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const tmp = this.filePath + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify({
      seen: Object.fromEntries(this.seen),
      cache: Object.fromEntries(this.cache),
    }));
    fs.renameSync(tmp, this.filePath);
  }

  hasSeenProofTx(proofTx) {
    return this.seen.has(String(proofTx).toLowerCase());
  }

  markSeenProofTx(proofTx, taskId) {
    this.seen.set(String(proofTx).toLowerCase(), taskId);
  }

  getCached(taskId) {
    return this.cache.get(taskId) || null;
  }

  setCached(taskId, rawBody) {
    this.cache.set(taskId, rawBody);
  }
}
