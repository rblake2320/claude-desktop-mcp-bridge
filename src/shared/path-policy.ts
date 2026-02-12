/**
 * Path Policy - Security Gate
 *
 * Restricts filesystem writes to approved directories.
 * Prevents path traversal and escape attacks.
 */

import { resolve, sep } from 'node:path';
import { platform } from 'node:os';

const isWindows = platform() === 'win32';

/**
 * Normalize a path for consistent comparison.
 * On Windows, converts to lowercase and normalizes separators.
 */
function normalizePath(p: string): string {
  const resolved = resolve(p);
  return isWindows ? resolved.toLowerCase().replace(/\//g, '\\') : resolved;
}

/**
 * Assert that a target path is under the given root directory.
 * Throws if the path escapes the root.
 */
export function assertPathUnder(root: string, target: string): void {
  const normalizedRoot = normalizePath(root);
  const normalizedTarget = normalizePath(target);

  if (!normalizedTarget.startsWith(normalizedRoot + sep)) {
    throw new Error(
      `Path escape blocked. root=${root} target=${target}`
    );
  }
}

/**
 * Assert that a target path is within <repoPath>/.compliance/
 * This is the only directory the compliance-bridge is allowed to write to.
 */
export function assertCompliancePath(repoPath: string, target: string): void {
  const complianceRoot = resolve(repoPath, '.compliance');
  assertPathUnder(complianceRoot, target);
}

/**
 * Validate that a repo path looks reasonable (exists check is done at call site).
 * Blocks obvious traversal patterns in the input string itself.
 */
export function validateRepoPath(repoPath: string): { valid: boolean; reason?: string } {
  if (!repoPath || repoPath.trim().length === 0) {
    return { valid: false, reason: 'Empty path' };
  }

  // Block obvious traversal patterns
  const traversalPatterns = [/\.\.[\\/]/, /\.\.$/];
  for (const pattern of traversalPatterns) {
    if (pattern.test(repoPath)) {
      return { valid: false, reason: 'Path contains traversal pattern' };
    }
  }

  // Block null bytes
  if (repoPath.includes('\0')) {
    return { valid: false, reason: 'Path contains null byte' };
  }

  return { valid: true };
}
