/**
 * Compliance Navigator - Zod Validation Schemas
 *
 * Input validation for all 7 compliance-bridge tools.
 */

import { z } from 'zod';

const PATH_TRAVERSAL = /\.\.[/\\]/;
const NULL_BYTE = /\0/;

const safePath = z.string()
  .min(1, 'Path is required')
  .max(1000, 'Path too long')
  .refine(p => !PATH_TRAVERSAL.test(p), 'Path contains traversal pattern')
  .refine(p => !NULL_BYTE.test(p), 'Path contains null byte');

export const ScanRepoSchema = z.object({
  framework: z.literal('soc2').default('soc2'),
  repoPath: safePath,
  mode: z.enum(['report-only', 'generate-remediation']).default('report-only'),
  includePaths: z.array(z.string()).optional(),
  excludePaths: z.array(z.string()).optional(),
  maxMinutes: z.number().min(1).max(60).default(10),
});

export const GenerateAuditPacketSchema = z.object({
  repoPath: safePath,
  runId: z.string().optional(),
  outputDir: z.string().optional(),
});

export const PlanRemediationSchema = z.object({
  repoPath: safePath,
  runId: z.string().optional(),
  mode: z.enum(['report-only', 'generate-remediation']).default('report-only'),
  maxItems: z.number().min(1).max(100).default(20),
});

export const CreateTicketsSchema = z.object({
  repoPath: safePath,
  runId: z.string().optional(),
  maxItems: z.number().min(1).max(100).default(10),
  target: z.enum(['github', 'jira']).default('github'),
  targetRepo: z.string().min(1).max(200).regex(
    /^[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)?$/,
    'Must be owner/name (GitHub) or PROJECT_KEY (Jira)'
  ).optional(),
  dryRun: z.boolean().default(true),
  approvedPlanId: z.string().optional(),
  reopenClosed: z.boolean().default(false),
  labelPolicy: z.enum(['require-existing', 'create-if-missing']).default('require-existing'),
}).strict();

export const ApproveTicketPlanSchema = z.object({
  repoPath: safePath,
  planId: z.string().min(6),
  approvedBy: z.string().min(1),
  reason: z.string().optional(),
}).strict();

export const VerifyAuditChainSchema = z.object({
  logPath: z.string().optional(),
}).strict();

export const OpenDashboardSchema = z.object({
  repoPath: safePath,
  runId: z.string().optional(),
}).strict();

export type OpenDashboardInput = z.infer<typeof OpenDashboardSchema>;

export type ScanRepoInput = z.infer<typeof ScanRepoSchema>;
export type GenerateAuditPacketInput = z.infer<typeof GenerateAuditPacketSchema>;
export type PlanRemediationInput = z.infer<typeof PlanRemediationSchema>;
export type CreateTicketsInput = z.infer<typeof CreateTicketsSchema>;
export type ApproveTicketPlanInput = z.infer<typeof ApproveTicketPlanSchema>;
export type VerifyAuditChainInput = z.infer<typeof VerifyAuditChainSchema>;
