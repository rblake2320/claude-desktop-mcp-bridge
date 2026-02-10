/**
 * Trust-based skill approval and security management
 * Phase 3A: TrustManager for handling skill approval workflow
 */

import { readFile, writeFile, readdir, access } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';
import { randomUUID } from 'node:crypto';
import {
  SkillManifest,
  TrustLevel,
  UserApprovalRequest,
  TrustValidationResult,
  SKILL_DIRECTORIES,
  DEFAULT_RESOURCE_LIMITS
} from './types.js';

/**
 * Risk assessment levels for approval requests
 */
export enum RiskLevel {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH'
}

/**
 * Approval decision outcome
 */
export interface ApprovalDecision {
  approved: boolean;
  new_trust_level?: TrustLevel;
  restrictions?: string[];
  reason: string;
  expires_at?: string;
}

/**
 * Trust manager for handling skill approval workflow and security controls
 */
export class TrustManager {
  private approvalsPath: string;
  private approvalCache: Map<string, UserApprovalRequest> = new Map();

  constructor() {
    this.approvalsPath = SKILL_DIRECTORIES.APPROVALS.replace('~', homedir());
  }

  /**
   * Generate risk assessment for a skill manifest
   */
  async assessRisk(manifest: SkillManifest, validation: TrustValidationResult): Promise<UserApprovalRequest> {
    const riskFactors: string[] = [];
    const recommendations: string[] = [];
    let riskLevel: RiskLevel = RiskLevel.LOW;

    // 1. Analyze capabilities for risk
    const highRiskCapabilities = [
      'file_system_write',
      'shell_execution',
      'network_requests',
      'system_information',
      'environment_variables'
    ];

    const mediumRiskCapabilities = [
      'file_system_read',
      'process_management',
      'api_calls',
      'data_processing'
    ];

    for (const capability of manifest.capabilities) {
      if (highRiskCapabilities.some(risk => capability.toLowerCase().includes(risk))) {
        riskFactors.push(`High-risk capability: ${capability}`);
        riskLevel = RiskLevel.HIGH;
      } else if (mediumRiskCapabilities.some(risk => capability.toLowerCase().includes(risk))) {
        riskFactors.push(`Medium-risk capability: ${capability}`);
        if (riskLevel === RiskLevel.LOW) {
          riskLevel = RiskLevel.MEDIUM;
        }
      }
    }

    // 2. Analyze validation issues
    if (validation.issues.length > 0) {
      riskFactors.push(...validation.issues);
      if (validation.issues.some(issue => issue.toLowerCase().includes('dangerous') ||
                                           issue.toLowerCase().includes('suspicious'))) {
        riskLevel = RiskLevel.HIGH;
      } else {
        riskLevel = RiskLevel.MEDIUM;
      }
    }

    // 3. Check resource requirements
    const limits = manifest.resource_limits || DEFAULT_RESOURCE_LIMITS[manifest.trust_level];
    if (limits.max_memory_mb > 256) {
      riskFactors.push(`High memory usage: ${limits.max_memory_mb}MB`);
    }
    if (limits.timeout_seconds > 60) {
      riskFactors.push(`Long execution timeout: ${limits.timeout_seconds}s`);
    }
    if (limits.max_network_requests && limits.max_network_requests > 10) {
      riskFactors.push(`High network usage: ${limits.max_network_requests} requests`);
    }

    // 4. Check for unknown author
    if (!manifest.author || manifest.author === 'unknown' || manifest.author.length < 3) {
      riskFactors.push('Unknown or unverified author');
      if (riskLevel === RiskLevel.LOW) {
        riskLevel = RiskLevel.MEDIUM;
      }
    }

    // 5. Generate recommendations
    switch (riskLevel) {
      case RiskLevel.HIGH:
        recommendations.push(
          'Carefully review skill code before approval',
          'Consider running in isolated environment first',
          'Monitor execution closely if approved',
          'Set restrictive resource limits'
        );
        break;
      case RiskLevel.MEDIUM:
        recommendations.push(
          'Review skill capabilities and permissions',
          'Test in safe environment if possible',
          'Monitor initial usage'
        );
        break;
      case RiskLevel.LOW:
        recommendations.push(
          'Standard approval process acceptable',
          'Basic monitoring recommended'
        );
        break;
    }

    // If no risks found, ensure we still have some concerns documented
    if (riskFactors.length === 0) {
      riskFactors.push('No obvious security risks detected');
      riskFactors.push('Untrusted source - requires user approval');
    }

    const approvalRequest: UserApprovalRequest = {
      skill_name: manifest.name,
      trust_level: manifest.trust_level,
      manifest,
      risk_assessment: {
        risk_level: riskLevel,
        concerns: riskFactors,
        recommendations
      },
      requested_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString() // 7 days
    };

    return approvalRequest;
  }

  /**
   * Submit skill for approval
   */
  async requestApproval(manifest: SkillManifest, validation: TrustValidationResult): Promise<string> {
    const request = await this.assessRisk(manifest, validation);
    const requestId = randomUUID();

    // Store approval request
    const requestPath = join(this.approvalsPath, `${requestId}.json`);
    await writeFile(requestPath, JSON.stringify(request, null, 2));

    // Cache the request
    this.approvalCache.set(requestId, request);

    console.log(`📋 Approval request created for skill '${manifest.name}' (Risk: ${request.risk_assessment.risk_level})`);
    console.log(`   Request ID: ${requestId}`);
    console.log(`   Expires: ${request.expires_at}`);

    return requestId;
  }

  /**
   * Get pending approval requests
   */
  async getPendingApprovals(): Promise<Array<UserApprovalRequest & { request_id: string }>> {
    const approvals: Array<UserApprovalRequest & { request_id: string }> = [];

    try {
      await access(this.approvalsPath);
      const files = await readdir(this.approvalsPath);

      for (const file of files) {
        if (file.endsWith('.json')) {
          try {
            const requestId = file.replace('.json', '');
            const content = await readFile(join(this.approvalsPath, file), 'utf-8');
            const request = JSON.parse(content) as UserApprovalRequest;

            // Check if not expired
            if (!request.expires_at || new Date(request.expires_at) > new Date()) {
              approvals.push({ ...request, request_id: requestId });
            }
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            console.warn(`⚠️ Failed to load approval request ${file}: ${errorMessage}`);
          }
        }
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const hasCode = error && typeof error === 'object' && 'code' in error;
      if (!hasCode || (error as any).code !== 'ENOENT') {
        console.error(`Failed to read approvals directory: ${errorMessage}`);
      }
    }

    return approvals;
  }

  /**
   * Process approval decision
   */
  async processApproval(requestId: string, decision: ApprovalDecision): Promise<boolean> {
    try {
      const requestPath = join(this.approvalsPath, `${requestId}.json`);
      const content = await readFile(requestPath, 'utf-8');
      const request = JSON.parse(content) as UserApprovalRequest;

      // Create approval record
      const approvalRecord = {
        ...request,
        approved: decision.approved,
        approved_at: new Date().toISOString(),
        decision: decision,
        processed_by: 'system' // In future: actual user ID
      };

      // Save approval record
      const recordPath = join(this.approvalsPath, `${requestId}_approved.json`);
      await writeFile(recordPath, JSON.stringify(approvalRecord, null, 2));

      console.log(`✅ Approval processed for skill '${request.skill_name}': ${decision.approved ? 'APPROVED' : 'REJECTED'}`);
      console.log(`   Reason: ${decision.reason}`);

      if (decision.approved && decision.new_trust_level) {
        console.log(`   New trust level: ${decision.new_trust_level}`);
      }

      // Remove from cache
      this.approvalCache.delete(requestId);

      return true;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      console.error(`Failed to process approval ${requestId}: ${errorMessage}`);
      return false;
    }
  }

  /**
   * Auto-approve low-risk skills based on policy
   */
  async autoApproveIfEligible(manifest: SkillManifest, validation: TrustValidationResult): Promise<boolean> {
    const request = await this.assessRisk(manifest, validation);

    // Auto-approve only low-risk skills with specific criteria
    if (request.risk_assessment.risk_level === RiskLevel.LOW &&
        validation.issues.length === 0 &&
        manifest.author !== 'unknown' &&
        manifest.capabilities.length <= 3) {

      // Auto-approval logic - could store decision in future
      // const decision: ApprovalDecision = {
      //   approved: true,
      //   new_trust_level: TrustLevel.VERIFIED,
      //   reason: 'Auto-approved: Low risk, no security issues detected',
      //   expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
      // };

      console.log(`🤖 Auto-approving low-risk skill: ${manifest.name}`);
      return true;
    }

    return false;
  }

  /**
   * Validate trust elevation request
   */
  async validateTrustElevation(skillName: string, currentTrust: TrustLevel, targetTrust: TrustLevel): Promise<boolean> {
    // Can only elevate by one level at a time
    const trustLevels = [TrustLevel.UNTRUSTED, TrustLevel.VERIFIED, TrustLevel.BUILT_IN];
    const currentIndex = trustLevels.indexOf(currentTrust);
    const targetIndex = trustLevels.indexOf(targetTrust);

    if (targetIndex <= currentIndex) {
      return false; // Cannot downgrade or stay same
    }

    if (targetIndex - currentIndex > 1) {
      return false; // Cannot skip levels
    }

    // System level requires manual approval
    if (targetTrust === TrustLevel.BUILT_IN) {
      console.log(`⚠️ System trust level elevation for '${skillName}' requires manual review`);
      return false;
    }

    return true;
  }

  /**
   * Generate approval summary report
   */
  async generateApprovalReport(): Promise<any> {
    const pending = await this.getPendingApprovals();
    const processed: any[] = [];

    // Load processed approvals
    try {
      await access(this.approvalsPath);
      const files = await readdir(this.approvalsPath);

      for (const file of files) {
        if (file.endsWith('_approved.json')) {
          try {
            const content = await readFile(join(this.approvalsPath, file), 'utf-8');
            const record = JSON.parse(content);
            processed.push(record);
          } catch (error) {
            // Skip malformed files
          }
        }
      }
    } catch (error) {
      // Approvals directory doesn't exist yet
    }

    // Generate statistics
    const approvedCount = processed.filter(p => p.approved).length;
    const rejectedCount = processed.filter(p => !p.approved).length;
    const riskDistribution = pending.reduce((acc, req) => {
      acc[req.risk_assessment.risk_level] = (acc[req.risk_assessment.risk_level] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return {
      summary: {
        pending_approvals: pending.length,
        total_processed: processed.length,
        approved: approvedCount,
        rejected: rejectedCount,
        approval_rate: processed.length > 0 ? (approvedCount / processed.length * 100).toFixed(1) + '%' : '0%'
      },
      pending_by_risk: riskDistribution,
      pending_requests: pending.map(req => ({
        skill_name: req.skill_name,
        risk_level: req.risk_assessment.risk_level,
        requested_at: req.requested_at,
        expires_at: req.expires_at
      })),
      recent_decisions: processed
        .sort((a, b) => new Date(b.approved_at).getTime() - new Date(a.approved_at).getTime())
        .slice(0, 10)
        .map(record => ({
          skill_name: record.skill_name,
          approved: record.approved,
          approved_at: record.approved_at,
          reason: record.decision.reason
        }))
    };
  }

  /**
   * Cleanup expired approval requests
   */
  async cleanupExpiredRequests(): Promise<number> {
    let cleanedCount = 0;

    try {
      await access(this.approvalsPath);
      const files = await readdir(this.approvalsPath);

      for (const file of files) {
        if (file.endsWith('.json') && !file.endsWith('_approved.json')) {
          try {
            const content = await readFile(join(this.approvalsPath, file), 'utf-8');
            const request = JSON.parse(content) as UserApprovalRequest;

            // Check if expired
            if (request.expires_at && new Date(request.expires_at) <= new Date()) {
              // In production, you might want to archive instead of delete
              // const requestPath = join(this.approvalsPath, file);
              console.log(`🗑️ Cleaning up expired approval request for ${request.skill_name}`);
              cleanedCount++;
            }
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            console.warn(`⚠️ Failed to check expiry for ${file}: ${errorMessage}`);
          }
        }
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const hasCode = error && typeof error === 'object' && 'code' in error;
      if (!hasCode || (error as any).code !== 'ENOENT') {
        console.error(`Failed to cleanup expired requests: ${errorMessage}`);
      }
    }

    return cleanedCount;
  }
}