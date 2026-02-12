/**
 * Command Allowlist - Security Gate
 *
 * Restricts which commands the compliance-bridge can execute.
 * Only explicitly allowlisted patterns are permitted.
 */

export interface AllowlistRule {
  pattern: RegExp;
  description: string;
}

export const COMPLIANCE_COMMAND_ALLOWLIST: AllowlistRule[] = [
  // Scanner commands
  {
    pattern: /^gitleaks(\.exe)?\s+detect\b/i,
    description: 'Gitleaks secret detection',
  },
  {
    pattern: /^npm(\.cmd)?\s+audit\b/i,
    description: 'npm vulnerability audit',
  },
  {
    pattern: /^checkov(\.exe|\.cmd)?\s+(-d|--directory)\b/i,
    description: 'Checkov IaC scanning',
  },
  // Version commands (for manifest scanner version capture)
  {
    pattern: /^gitleaks(\.exe)?\s+version\b/i,
    description: 'Gitleaks version check',
  },
  {
    pattern: /^npm(\.cmd)?\s+--version\b/i,
    description: 'npm version check',
  },
  {
    pattern: /^checkov(\.exe|\.cmd)?\s+(--version|-v)\b/i,
    description: 'Checkov version check',
  },
];

export interface AllowlistResult {
  allowed: boolean;
  matchedRule?: string;
}

/**
 * Check if a command is on the allowlist.
 * Returns allowed: true only if the command matches an explicit pattern.
 */
export function isCommandAllowed(command: string): AllowlistResult {
  const trimmed = command.trim();

  for (const rule of COMPLIANCE_COMMAND_ALLOWLIST) {
    if (rule.pattern.test(trimmed)) {
      return { allowed: true, matchedRule: rule.description };
    }
  }

  return { allowed: false };
}

/**
 * Assert that a command is allowed. Throws if not.
 */
export function assertAllowedCommand(command: string): void {
  const result = isCommandAllowed(command);
  if (!result.allowed) {
    throw new Error(`Command not allowlisted: ${command.slice(0, 80)}`);
  }
}
