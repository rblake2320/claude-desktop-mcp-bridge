/**
 * Hash-Chained Audit Log
 *
 * Append-only JSONL log with SHA256 hash chain.
 * Each entry includes the hash of the previous entry,
 * creating a hash-linked chain where modifications are detectable
 * by recomputing hashes from the first entry.
 */

import { createHash } from 'node:crypto';
import { existsSync, readFileSync, appendFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export interface AuditEntry {
  ts: string;
  kind: string;
  tool?: string;
  data: Record<string, unknown>;
  prevHash: string;
  hash: string;
}

const GENESIS_HASH = 'GENESIS';

/**
 * Compute SHA256 hash of a payload object.
 */
function computeHash(payload: Record<string, unknown>): string {
  return createHash('sha256')
    .update(JSON.stringify(payload))
    .digest('hex');
}

/**
 * Append-only JSONL audit log with hash chain integrity.
 */
export class AuditChain {
  private logPath: string;

  constructor(logPath: string) {
    this.logPath = logPath;
    // Ensure directory exists
    const dir = dirname(logPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
  }

  /**
   * Get the hash of the last entry in the chain.
   * Returns GENESIS if the log is empty or doesn't exist.
   */
  private getLastHash(): string {
    if (!existsSync(this.logPath)) {
      return GENESIS_HASH;
    }

    const content = readFileSync(this.logPath, 'utf-8').trim();
    if (!content) {
      return GENESIS_HASH;
    }

    const lines = content.split('\n');
    const lastLine = lines[lines.length - 1];
    if (!lastLine) {
      return GENESIS_HASH;
    }

    try {
      const entry: AuditEntry = JSON.parse(lastLine);
      return entry.hash ?? GENESIS_HASH;
    } catch {
      return GENESIS_HASH;
    }
  }

  /**
   * Append a new event to the audit chain.
   */
  append(
    kind: string,
    tool: string | undefined,
    data: Record<string, unknown>
  ): void {
    const prevHash = this.getLastHash();
    const ts = new Date().toISOString();
    const payload = { ts, kind, tool, data, prevHash };
    const hash = computeHash(payload);

    const entry: AuditEntry = { ...payload, hash };
    appendFileSync(this.logPath, JSON.stringify(entry) + '\n', 'utf-8');
  }

  /**
   * Verify the integrity of the entire audit chain.
   * Recomputes every hash from entry 1 and checks each link.
   *
   * Returns detailed verification result including:
   *   - valid: whether all hashes check out
   *   - totalEntries: number of entries in the chain
   *   - firstEntry/lastEntry timestamps (for coverage range)
   *   - brokenAt: 1-indexed line number of first failure (if any)
   *   - brokenReason: human-readable description of what failed
   */
  verify(): VerifyResult {
    if (!existsSync(this.logPath)) {
      return { valid: true, totalEntries: 0, logPath: this.logPath };
    }

    const content = readFileSync(this.logPath, 'utf-8').trim();
    if (!content) {
      return { valid: true, totalEntries: 0, logPath: this.logPath };
    }

    const lines = content.split('\n');
    let expectedPrevHash = GENESIS_HASH;
    let firstTs: string | undefined;
    let lastTs: string | undefined;

    for (let i = 0; i < lines.length; i++) {
      let entry: AuditEntry;
      try {
        entry = JSON.parse(lines[i]);
      } catch {
        return {
          valid: false,
          brokenAt: i + 1,
          brokenReason: `Line ${i + 1}: invalid JSON`,
          totalEntries: lines.length,
          logPath: this.logPath,
        };
      }

      if (i === 0) firstTs = entry.ts;
      lastTs = entry.ts;

      // Check prevHash links to previous entry
      if (entry.prevHash !== expectedPrevHash) {
        return {
          valid: false,
          brokenAt: i + 1,
          brokenReason: `Line ${i + 1}: prevHash mismatch (expected ${expectedPrevHash.slice(0, 12)}..., got ${entry.prevHash.slice(0, 12)}...)`,
          totalEntries: lines.length,
          logPath: this.logPath,
          firstEntry: firstTs,
          lastEntry: lastTs,
        };
      }

      // Verify the hash of this entry
      const { hash: storedHash, ...payload } = entry;
      const computedHash = computeHash(payload);
      if (computedHash !== storedHash) {
        return {
          valid: false,
          brokenAt: i + 1,
          brokenReason: `Line ${i + 1}: hash mismatch (entry was modified after writing)`,
          totalEntries: lines.length,
          logPath: this.logPath,
          firstEntry: firstTs,
          lastEntry: lastTs,
        };
      }

      expectedPrevHash = storedHash;
    }

    return {
      valid: true,
      totalEntries: lines.length,
      logPath: this.logPath,
      firstEntry: firstTs,
      lastEntry: lastTs,
    };
  }
}

export interface VerifyResult {
  valid: boolean;
  brokenAt?: number;
  brokenReason?: string;
  totalEntries: number;
  logPath: string;
  firstEntry?: string;
  lastEntry?: string;
}
