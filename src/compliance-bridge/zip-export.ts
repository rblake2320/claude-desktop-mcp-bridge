/**
 * ZIP Export for Audit Packets
 *
 * Zips the audit_packet/ directory (and optionally evidence/) into a single
 * portable archive. Computes SHA-256 of the resulting ZIP for integrity
 * verification. Writes to <repo>/.compliance/exports/<runId>/
 */

import { createReadStream, existsSync, mkdirSync, statSync, readdirSync, lstatSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { createHash } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import archiver from 'archiver';
import { assertCompliancePath } from '../shared/path-policy.js';
import type { ExportAuditPacketResponse } from './contracts.js';

export type { ExportAuditPacketResponse };

// ── SHA-256 Utility ──────────────────────────────────────────────

function computeSha256(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    const stream = createReadStream(filePath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

// ── Symlink-safe directory walker ────────────────────────────────

/**
 * Recursively add files from a directory to the archive, skipping symlinks.
 * This prevents symlink-based data exfiltration attacks.
 */
function addDirectorySafe(
  archive: archiver.Archiver,
  dirPath: string,
  destPrefix: string,
): void {
  const entries = readdirSync(dirPath, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = join(dirPath, entry.name);
    const destPath = destPrefix ? `${destPrefix}/${entry.name}` : entry.name;

    // Skip symlinks entirely — prevents exfiltration via symlink attacks
    const stat = lstatSync(fullPath);
    if (stat.isSymbolicLink()) {
      continue;
    }

    if (stat.isDirectory()) {
      addDirectorySafe(archive, fullPath, destPath);
    } else if (stat.isFile()) {
      archive.file(fullPath, { name: destPath });
    }
  }
}

// ── ZIP Generator ────────────────────────────────────────────────

/**
 * Create a ZIP archive of an audit packet.
 *
 * Reads audit_packet/ (and optionally evidence/) from the run directory,
 * writes the zip to .compliance/exports/<runId>/audit_packet.zip.
 */
export function exportAuditPacket(
  repoPath: string,
  runId: string,
  includeEvidence: boolean,
): Promise<ExportAuditPacketResponse> {
  return new Promise((resolvePromise, rejectPromise) => {
    const runDir = resolve(repoPath, '.compliance', 'runs', runId);
    const packetDir = resolve(runDir, 'audit_packet');

    // Security: verify read sources are under .compliance/
    assertCompliancePath(repoPath, resolve(packetDir, 'placeholder'));

    if (!existsSync(packetDir)) {
      rejectPromise(new Error(
        `Audit packet not found at ${packetDir}. Run compliance.generate_audit_packet first.`
      ));
      return;
    }

    // Output location: .compliance/exports/<runId>/
    const exportsDir = resolve(repoPath, '.compliance', 'exports', runId);
    const zipPath = resolve(exportsDir, 'audit_packet.zip');

    // Security: verify write target is under .compliance/
    assertCompliancePath(repoPath, zipPath);

    mkdirSync(exportsDir, { recursive: true });

    const output = createWriteStream(zipPath);
    const archive = archiver('zip', { zlib: { level: 9 } });

    let finalized = false;

    output.on('close', async () => {
      if (finalized) return;
      finalized = true;

      try {
        const stats = statSync(zipPath);
        const sha256 = await computeSha256(zipPath);

        resolvePromise({
          zipPath,
          bytes: stats.size,
          sha256,
          runId,
          includesEvidence: includeEvidence,
        });
      } catch (err) {
        rejectPromise(err);
      }
    });

    output.on('error', (err) => {
      if (!finalized) {
        finalized = true;
        archive.destroy();
        rejectPromise(err);
      }
    });

    archive.on('error', (err) => {
      if (!finalized) {
        finalized = true;
        output.destroy();
        rejectPromise(err);
      }
    });

    archive.pipe(output);

    // Add audit_packet/ contents at the root of the zip (symlink-safe)
    addDirectorySafe(archive, packetDir, 'audit_packet');

    // Optionally include the evidence/ directory from the run
    if (includeEvidence) {
      const evidenceDir = resolve(runDir, 'evidence');
      // Security: verify evidence read source is under .compliance/
      assertCompliancePath(repoPath, resolve(evidenceDir, 'placeholder'));
      if (existsSync(evidenceDir)) {
        addDirectorySafe(archive, evidenceDir, 'evidence');
      }
    }

    archive.finalize();
  });
}
