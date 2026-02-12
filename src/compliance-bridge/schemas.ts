/**
 * Compliance Navigator - Zod Validation Schemas
 *
 * Input validation for all 3 compliance-bridge tools.
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

export type ScanRepoInput = z.infer<typeof ScanRepoSchema>;
export type GenerateAuditPacketInput = z.infer<typeof GenerateAuditPacketSchema>;
export type PlanRemediationInput = z.infer<typeof PlanRemediationSchema>;
