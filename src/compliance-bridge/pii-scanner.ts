/**
 * PII/PHI Detector Scanner (built-in)
 *
 * Native TypeScript scanner that detects personally identifiable information
 * (PII) and protected health information (PHI) indicators in repository files.
 * Runs in-process alongside gitleaks / npm audit / checkov — no external
 * binary, no shell execution, no network access.
 *
 * Detection approach: validator-backed pattern matching.
 *   - SSN: structural validation (area/group/serial rules), dashed form
 *     matched directly; undashed 9-digit form requires an "ssn" context
 *     keyword on the same line to avoid flagging arbitrary numbers.
 *   - Credit card: 13-19 digits, Luhn checksum + known IIN prefix required.
 *   - Email: conservative pattern; role addresses (noreply) and reserved
 *     example/test domains are excluded as documented false-positive filters.
 *   - Phone / DOB / MRN: context-gated (keyword must appear on the line).
 *
 * SCOPE LIMITATIONS (by design, documented): free-text person names and
 * postal addresses require NER models and are NOT detected. DOB matching is
 * biased to US date order (MM/DD or ISO); day-first dates are rejected.
 * Do not present this scanner as exhaustive PII discovery.
 *
 * REDACTION: findings and evidence artifacts never contain the raw matched
 * value. Masks: SSN and payment cards keep the last 4 digits (industry
 * convention); MRNs are fully masked (short identifiers must not leak);
 * emails keep the first character and the TLD only (j***@***.org); DOBs are
 * fully masked. Masked forms are partial by definition — treat audit packets
 * as sensitive documents regardless.
 *
 * PERFORMANCE NOTE: the scan is synchronous (blocks the event loop while it
 * runs). It is bounded by per-file deadline checks, MAX file/size/line caps,
 * and backtracking-safe patterns; worst-case blocking is one file's scan.
 */

import { readdirSync, readFileSync, statSync, existsSync, realpathSync } from 'node:fs';
import { resolve, relative, sep, extname } from 'node:path';
import { createHash } from 'node:crypto';
import type { NormalizedFinding, Severity } from './contracts.js';

// ── Limits (documented, reported in stats — never silently applied) ──

const DEFAULT_MAX_FILE_BYTES = 1024 * 1024;      // 1 MiB per file
const DEFAULT_MAX_FILES = 50_000;                // total files walked
const DEFAULT_MAX_FINDINGS_PER_RULE_PER_FILE = 25;
const MAX_LINE_LENGTH = 10_000;                  // minified/generated lines skipped
const BINARY_SNIFF_BYTES = 8_192;
const DEADLINE_CHECK_EVERY_LINES = 25;

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.compliance', 'dist', 'build', 'out', 'coverage',
  'vendor', '.venv', 'venv', '__pycache__', '.next', '.terraform', 'target',
]);

const SKIP_FILES = new Set([
  'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'composer.lock',
  'Cargo.lock', 'poetry.lock', 'Gemfile.lock',
]);

const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.bmp', '.webp', '.pdf',
  '.zip', '.gz', '.tar', '.tgz', '.7z', '.rar', '.jar', '.war',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.class', '.pyc', '.wasm',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.mp3', '.mp4', '.mov', '.avi', '.mkv', '.flac', '.ogg',
]);

// ── Validators (exported for unit testing) ───────────────────────

/** Luhn checksum over a digits-only string. */
export function luhnValid(digits: string): boolean {
  if (!/^\d+$/.test(digits)) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

/**
 * SSN structural validation per SSA issuance rules:
 * area 001-899 excluding 666; group 01-99; serial 0001-9999.
 */
export function isValidSSN(area: string, group: string, serial: string): boolean {
  const a = Number(area);
  if (a === 0 || a === 666 || a >= 900) return false;
  if (Number(group) === 0) return false;
  if (Number(serial) === 0) return false;
  return true;
}

/** Known issuer (IIN) prefix + length check for payment card numbers. */
export function matchesKnownIIN(digits: string): boolean {
  const len = digits.length;
  if (/^4/.test(digits)) return len === 13 || len === 16 || len === 19;               // Visa
  if (/^5[1-5]/.test(digits)) return len === 16;                                       // Mastercard
  const four = Number(digits.slice(0, 4));
  if (four >= 2221 && four <= 2720) return len === 16;                                 // Mastercard 2-series
  if (/^3[47]/.test(digits)) return len === 15;                                        // Amex
  if (/^(6011|65|64[4-9])/.test(digits)) return len >= 16 && len <= 19;                // Discover
  if (/^35(2[89]|[3-8]\d)/.test(digits)) return len >= 16 && len <= 19;                // JCB
  if (/^3(0[0-5]|[68])/.test(digits)) return len >= 14 && len <= 19;                   // Diners
  return false;
}

// ── Masking ──────────────────────────────────────────────────────

/** Mask all digits except the last 4, preserving separators: ***-**-1120 */
function maskKeepLast4(value: string): string {
  const digitPositions: number[] = [];
  for (let i = 0; i < value.length; i++) {
    if (value[i] >= '0' && value[i] <= '9') digitPositions.push(i);
  }
  const keep = new Set(digitPositions.slice(-4));
  let out = '';
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    out += (c >= '0' && c <= '9' && !keep.has(i)) ? '*' : c;
  }
  return out;
}

/** Mask everything except the local part's first char and the TLD: j***@***.org */
function maskEmail(value: string): string {
  const at = value.indexOf('@');
  const lastDot = value.lastIndexOf('.');
  if (at <= 0 || lastDot <= at) return '***';
  return value[0] + '***@***' + value.slice(lastDot);
}

/** Mask every digit — for short identifiers where last-4 would leak most of the value. */
function maskAllDigits(value: string): string {
  return value.replace(/\d/g, '*');
}

// ── Rules ────────────────────────────────────────────────────────

export interface PIIRule {
  id: string;
  title: string;
  severity: Severity;
  /** If set, the line must match this (case-insensitive) before the pattern runs. */
  contextRequired?: RegExp;
  pattern: RegExp;   // must use the 'g' flag
  /** Return false to reject a raw match (validator layer). */
  validate?: (match: string) => boolean;
  mask: (match: string) => string;
  remediation: string;
  tags: string[];
}

const EXCLUDED_EMAIL_DOMAIN = /(^|\.)(example\.(com|org|net)|example|test|invalid|localhost|local)$/i;
const EXCLUDED_EMAIL_LOCAL = /^(noreply|no-reply|donotreply)$/i;

export const PII_RULES: PIIRule[] = [
  {
    id: 'ssn',
    title: 'US Social Security Number',
    severity: 'high',
    pattern: /\b(\d{3})-(\d{2})-(\d{4})\b/g,
    validate: (m) => {
      const parts = m.split('-');
      return isValidSSN(parts[0], parts[1], parts[2]);
    },
    mask: maskKeepLast4,
    remediation: 'Remove the SSN from source control, scrub git history if committed, and store such identifiers only in access-controlled, encrypted systems.',
    tags: ['pii', 'ssn'],
  },
  {
    id: 'ssn-context',
    title: 'US Social Security Number (undashed, context-matched)',
    severity: 'high',
    contextRequired: /\bssn\b|social.?security/i,
    pattern: /\b(\d{9})\b/g,
    validate: (m) => isValidSSN(m.slice(0, 3), m.slice(3, 5), m.slice(5)),
    mask: maskKeepLast4,
    remediation: 'Remove the SSN from source control, scrub git history if committed, and store such identifiers only in access-controlled, encrypted systems.',
    tags: ['pii', 'ssn'],
  },
  {
    id: 'credit-card',
    title: 'Payment card number (Luhn-valid, known issuer)',
    severity: 'high',
    pattern: /\b(?:\d[ -]?){12,18}\d\b/g,
    validate: (m) => {
      const digits = m.replace(/[ -]/g, '');
      return digits.length >= 13 && digits.length <= 19
        && luhnValid(digits) && matchesKnownIIN(digits);
    },
    mask: maskKeepLast4,
    remediation: 'Remove the card number from source control. Storing PANs in code violates PCI DSS; use tokenization via your payment processor.',
    tags: ['pii', 'credit-card'],
  },
  {
    id: 'email',
    title: 'Email address',
    severity: 'low',
    // Domain alternation is unambiguous (no class overlaps the literal dot) — avoids polynomial backtracking
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*\.[A-Za-z]{2,}\b/g,
    validate: (m) => {
      const [local, domain] = m.split('@');
      if (EXCLUDED_EMAIL_LOCAL.test(local)) return false;
      if (EXCLUDED_EMAIL_DOMAIN.test(domain)) return false;
      return true;
    },
    mask: maskEmail,
    remediation: 'Review whether this email address is personal data that belongs in source control; replace with a placeholder or configuration value if not.',
    tags: ['pii', 'email'],
  },
  {
    id: 'phone-us',
    title: 'US phone number (context-matched)',
    severity: 'low',
    contextRequired: /\b(phone|tel|telephone|mobile|cell|fax)\b/i,
    pattern: /(?<!\d)(?:\+?1[ .-]?)?\(?([2-9]\d{2})\)?[ .-]([2-9]\d{2})[ .-](\d{4})\b/g,
    mask: maskKeepLast4,
    remediation: 'Replace real phone numbers with reserved fictional ranges (e.g. 555-01XX) or move them to access-controlled data stores.',
    tags: ['pii', 'phone'],
  },
  {
    id: 'dob',
    title: 'Date of birth (context-matched)',
    severity: 'medium',
    contextRequired: /\b(dob|date[ _-]?of[ _-]?birth|birth ?date|born)\b/i,
    pattern: /\b(?:\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]\d{2,4})\b/g,
    validate: (m) => {
      const parts = m.split(/[-/]/).map(Number);
      const [a, b, c] = parts;
      if (m.match(/^\d{4}/)) {
        return a >= 1900 && a <= 2100 && b >= 1 && b <= 12 && c >= 1 && c <= 31;
      }
      return a >= 1 && a <= 12 && b >= 1 && b <= 31;
    },
    mask: () => '****-**-** (redacted date)',
    remediation: 'Dates of birth are HIPAA identifiers. Remove from source control and store only in systems with appropriate PHI safeguards.',
    tags: ['pii', 'phi-indicator', 'dob'],
  },
  {
    id: 'mrn',
    title: 'Medical record number (context-matched)',
    severity: 'high',
    contextRequired: /\bmrn\b|medical record (number|no\.?|#)/i,
    pattern: /\b\d{5,10}\b/g,
    // Fully masked: a 5-digit MRN with last-4 kept would leak 80% of the value
    mask: maskAllDigits,
    remediation: 'Medical record numbers are PHI. Remove from source control, scrub git history, and audit how the data reached the repository.',
    tags: ['pii', 'phi-indicator', 'mrn'],
  },
];

// ── Scan types ───────────────────────────────────────────────────

export interface PIIScanStats {
  filesScanned: number;
  filesSkippedBinary: number;
  filesSkippedSize: number;
  filesSkippedSymlink: number;
  filesSkippedName: number;      // lock files etc.
  linesSkippedLong: number;
  readErrors: number;
  findingsCapped: number;        // matches dropped by the per-rule-per-file cap
  fileLimitReached: boolean;
  deadlineExceeded: boolean;
}

export interface PIIScanOptions {
  /** Absolute epoch-ms deadline. Scan stops (loudly) when exceeded. */
  deadlineMs?: number;
  maxFileBytes?: number;
  maxFiles?: number;
  maxFindingsPerRulePerFile?: number;
}

export interface PIIScanResult {
  findings: NormalizedFinding[];
  stats: PIIScanStats;
}

// ── Helpers ──────────────────────────────────────────────────────

function makeFindingId(input: Record<string, unknown>): string {
  return createHash('sha256')
    .update(JSON.stringify(input))
    .digest('hex')
    .slice(0, 16);
}

function looksBinary(buf: Buffer): boolean {
  const limit = Math.min(buf.length, BINARY_SNIFF_BYTES);
  for (let i = 0; i < limit; i++) {
    if (buf[i] === 0) return true;
  }
  return false;
}

/** Summarize stats into a single status message line. */
export function statsMessage(stats: PIIScanStats): string {
  const parts = [
    `scanned ${stats.filesScanned} files`,
    `skipped: ${stats.filesSkippedBinary} binary, ${stats.filesSkippedSize} oversize, ` +
    `${stats.filesSkippedSymlink} symlinks, ${stats.filesSkippedName} lock/vendored`,
  ];
  if (stats.linesSkippedLong > 0) parts.push(`${stats.linesSkippedLong} over-long lines skipped`);
  if (stats.readErrors > 0) parts.push(`${stats.readErrors} read errors`);
  if (stats.findingsCapped > 0) parts.push(`${stats.findingsCapped} matches dropped by per-file cap`);
  if (stats.fileLimitReached) parts.push('FILE LIMIT REACHED — scan is partial');
  if (stats.deadlineExceeded) parts.push('TIME BUDGET EXCEEDED — scan is partial');
  return parts.join('; ');
}

// ── Scanner ──────────────────────────────────────────────────────

/**
 * Scan a repository directory tree for PII/PHI indicators.
 *
 * @param repoPath    - Absolute path to the repository root (must exist)
 * @param evidenceRef - Path recorded on each finding's evidence pointer
 * @param opts        - Limits and deadline
 */
export function scanRepoForPII(
  repoPath: string,
  evidenceRef: string,
  opts: PIIScanOptions = {},
): PIIScanResult {
  if (!existsSync(repoPath)) {
    throw new Error(`PII scan: repository path does not exist: ${repoPath}`);
  }

  const maxFileBytes = opts.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const maxFiles = opts.maxFiles ?? DEFAULT_MAX_FILES;
  const capPerRulePerFile = opts.maxFindingsPerRulePerFile ?? DEFAULT_MAX_FINDINGS_PER_RULE_PER_FILE;
  const deadlineMs = opts.deadlineMs ?? Number.POSITIVE_INFINITY;

  const stats: PIIScanStats = {
    filesScanned: 0,
    filesSkippedBinary: 0,
    filesSkippedSize: 0,
    filesSkippedSymlink: 0,
    filesSkippedName: 0,
    linesSkippedLong: 0,
    readErrors: 0,
    findingsCapped: 0,
    fileLimitReached: false,
    deadlineExceeded: false,
  };
  const findings: NormalizedFinding[] = [];
  const seenIds = new Set<string>();

  // Containment root for the realpath backstop below
  let repoReal: string;
  try {
    repoReal = realpathSync(repoPath);
  } catch {
    throw new Error(`PII scan: cannot resolve repository path: ${repoPath}`);
  }

  // Iterative walk — avoids recursion depth limits on deep trees
  const dirStack: string[] = [repoPath];
  let filesVisited = 0;

  while (dirStack.length > 0) {
    if (Date.now() > deadlineMs) { stats.deadlineExceeded = true; break; }
    const dir = dirStack.pop() as string;

    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      stats.readErrors++;
      continue;
    }

    for (const entry of entries) {
      // Per-file deadline check — a directory full of small files must not
      // run past the time budget between the per-directory checks.
      if (Date.now() > deadlineMs) { stats.deadlineExceeded = true; break; }

      if (entry.isSymbolicLink()) { stats.filesSkippedSymlink++; continue; }

      const fullPath = resolve(dir, entry.name);

      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        // Defense-in-depth: even if a reparse point is reported as a plain
        // directory, never descend outside the repository root.
        try {
          const real = realpathSync(fullPath);
          if (real !== repoReal && !real.startsWith(repoReal + sep)) {
            stats.filesSkippedSymlink++;
            continue;
          }
        } catch {
          stats.readErrors++;
          continue;
        }
        dirStack.push(fullPath);
        continue;
      }
      if (!entry.isFile()) continue;

      if (filesVisited >= maxFiles) { stats.fileLimitReached = true; break; }
      filesVisited++;

      if (SKIP_FILES.has(entry.name) || BINARY_EXTENSIONS.has(extname(entry.name).toLowerCase())) {
        stats.filesSkippedName += SKIP_FILES.has(entry.name) ? 1 : 0;
        stats.filesSkippedBinary += SKIP_FILES.has(entry.name) ? 0 : 1;
        continue;
      }

      let buf: Buffer;
      try {
        const st = statSync(fullPath);
        if (st.size > maxFileBytes) { stats.filesSkippedSize++; continue; }
        buf = readFileSync(fullPath);
      } catch {
        stats.readErrors++;
        continue;
      }

      if (looksBinary(buf)) { stats.filesSkippedBinary++; continue; }

      const relPath = relative(repoPath, fullPath).split(sep).join('/');
      scanFileContent(buf.toString('utf-8'), relPath, evidenceRef, findings, seenIds, stats, capPerRulePerFile, deadlineMs);
      stats.filesScanned++;

      if (stats.deadlineExceeded) break;
    }

    if (stats.fileLimitReached || stats.deadlineExceeded) break;
  }

  return { findings, stats };
}

/** Scan a single file's text content. Exposed for unit testing. */
export function scanFileContent(
  content: string,
  relPath: string,
  evidenceRef: string,
  findings: NormalizedFinding[],
  seenIds: Set<string>,
  stats: PIIScanStats,
  capPerRulePerFile: number = DEFAULT_MAX_FINDINGS_PER_RULE_PER_FILE,
  deadlineMs: number = Number.POSITIVE_INFINITY,
): void {
  // Handles LF, CRLF, and CR-only (classic Mac) line endings
  const lines = content.split(/\r\n|\r|\n/);
  const perRuleCount = new Map<string, number>();

  for (let i = 0; i < lines.length; i++) {
    if (i % DEADLINE_CHECK_EVERY_LINES === 0 && Date.now() > deadlineMs) {
      stats.deadlineExceeded = true;
      return;
    }

    const line = lines[i];
    if (line.length > MAX_LINE_LENGTH) { stats.linesSkippedLong++; continue; }
    if (line.length === 0) continue;

    for (const rule of PII_RULES) {
      if (rule.contextRequired && !rule.contextRequired.test(line)) continue;

      rule.pattern.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = rule.pattern.exec(line)) !== null) {
        const raw = m[0];
        if (rule.validate && !rule.validate(raw)) continue;

        const count = perRuleCount.get(rule.id) ?? 0;
        if (count >= capPerRulePerFile) {
          stats.findingsCapped++;
          continue;
        }

        const masked = rule.mask(raw);
        // pos disambiguates distinct values on the same line that share a mask
        // (e.g. two different SSNs with the same last 4 digits)
        const id = makeFindingId({
          scanner: 'pii', rule: rule.id, file: relPath, line: i + 1, masked, pos: m.index,
        });
        if (seenIds.has(id)) continue;
        seenIds.add(id);
        perRuleCount.set(rule.id, count + 1);

        findings.push({
          id,
          scanner: 'pii',
          severity: rule.severity,
          title: `PII detected: ${rule.title} (${masked})`,
          description: `${rule.title} detected in ${relPath}:${i + 1}. The matched value is redacted; only the masked form shown in the title is recorded.`,
          file: relPath,
          line: i + 1,
          evidence: { kind: 'scanner_native', ref: evidenceRef },
          remediation: rule.remediation,
          tags: [...rule.tags],
        });
      }
    }
  }
}
