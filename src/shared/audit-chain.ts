/**
 * Tamper-Evident Audit Chain
 *
 * Append-only JSONL log with SHA256 hash chain.
 * Each entry includes the hash of the previous entry,
 * creating a tamper-evident chain of events.
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
   * Returns { valid: true } if the chain is intact,
   * or { valid: false, brokenAt: lineNumber } if tampered.
   */
  verify(): { valid: boolean; brokenAt?: number; totalEntries: number } {
    if (!existsSync(this.logPath)) {
      return { valid: true, totalEntries: 0 };
    }

    const content = readFileSync(this.logPath, 'utf-8').trim();
    if (!content) {
      return { valid: true, totalEntries: 0 };
    }

    const lines = content.split('\n');
    let expectedPrevHash = GENESIS_HASH;

    for (let i = 0; i < lines.length; i++) {
      let entry: AuditEntry;
      try {
        entry = JSON.parse(lines[i]);
      } catch {
        return { valid: false, brokenAt: i + 1, totalEntries: lines.length };
      }

      // Check prevHash links to previous entry
      if (entry.prevHash !== expectedPrevHash) {
        return { valid: false, brokenAt: i + 1, totalEntries: lines.length };
      }

      // Verify the hash of this entry
      const { hash: storedHash, ...payload } = entry;
      const computedHash = computeHash(payload);
      if (computedHash !== storedHash) {
        return { valid: false, brokenAt: i + 1, totalEntries: lines.length };
      }

      expectedPrevHash = storedHash;
    }

    return { valid: true, totalEntries: lines.length };
  }
}
