/**
 * Compliance Navigator - Risk Policy
 *
 * Per-tool risk tiers and approval requirements.
 */

import type { RiskTier } from './contracts.js';

export const TOOL_RISK: Record<string, RiskTier> = {
  'compliance.scan_repo': 'medium',
  'compliance.generate_audit_packet': 'medium',
  'compliance.plan_remediation': 'low',
  'compliance.create_tickets': 'high',
  'compliance.approve_ticket_plan': 'high',
  'compliance.verify_audit_chain': 'low',
  'compliance.open_dashboard': 'low',
  'compliance.create_demo_fixture': 'low',
};

/**
 * Check if a tool requires explicit user approval before execution.
 * Currently only HIGH risk tools require approval.
 */
export function requiresApproval(toolName: string): boolean {
  return TOOL_RISK[toolName] === 'high';
}

/**
 * Get the risk tier for a tool. Defaults to 'high' for unknown tools.
 */
export function getToolRisk(toolName: string): RiskTier {
  return TOOL_RISK[toolName] ?? 'high';
}
