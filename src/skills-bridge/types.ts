/**
 * Types and interfaces for dynamic skill loading system
 * Phase 3A: Foundation components for trust-based skill management
 */

export enum TrustLevel {
  BUILT_IN = "built-in",  // Built-in skills (full access)
  VERIFIED = "verified",  // Signed by trusted authority
  UNTRUSTED = "untrusted" // User-imported (sandboxed)
}

export enum SkillCategory {
  STANDARD = "standard",
  UTILITY = "utility",
  DEVELOPMENT = "development",
  SECURITY = "security",
  EXPERIMENTAL = "experimental"
}

export interface SkillResourceLimits {
  max_memory_mb: number;
  timeout_seconds: number;
  max_file_size_mb: number;
  allowed_domains?: string[];
  max_network_requests?: number;
}

export interface SkillManifest {
  // Core Metadata
  name: string;
  version: string;
  author: string;
  created: string;
  updated: string;

  // Security & Trust
  trust_level: TrustLevel;
  integrity_hash: string;     // SHA256 of skill content
  signature?: string;         // Digital signature for verified skills

  // Capabilities & Permissions
  capabilities: string[];
  required_permissions: string[];
  resource_limits: SkillResourceLimits;

  // Skill Definition
  description: string;
  category: SkillCategory;
  triggers: string[];
  pairs_with: string[];

  // File Paths (for dynamic loading)
  skill_file_path?: string;   // Path to skill implementation
  manifest_path?: string;     // Path to this manifest file
}

export interface SkillDefinition {
  // Existing skill definition structure (for backwards compatibility)
  name: string;
  description: string;
  capabilities: string[];
  category: SkillCategory;
  triggers: string[];
  pairsWith: string[];

  // Enhanced fields for dynamic loading
  manifest?: SkillManifest;
  trust_level: TrustLevel;
  loaded_from_path?: string;
  last_loaded: string;
}

export interface TrustValidationResult {
  valid: boolean;
  trust_level: TrustLevel;
  issues: string[];
  reason?: string;
  requires_approval?: boolean;
}

export interface SkillExecutionContext {
  skill_name: string;
  trust_level: TrustLevel;
  resource_limits: SkillResourceLimits;
  execution_id: string;
  start_time: string;
}

export interface SkillExecutionResult {
  success: boolean;
  output: string;
  execution_time_ms: number;
  resources_used: {
    memory_mb: number;
    network_requests: number;
  };
  security_events: string[];
  error?: string;
}

export interface SkillRegistryEntry {
  id: string;
  name: string;
  manifest: SkillManifest;
  definition: SkillDefinition;
  registered_at: string;
  last_used?: string;
  usage_count: number;
  status: 'active' | 'disabled' | 'pending_approval';
}

export interface UserApprovalRequest {
  skill_name: string;
  trust_level: TrustLevel;
  manifest: SkillManifest;
  risk_assessment: {
    risk_level: 'LOW' | 'MEDIUM' | 'HIGH';
    concerns: string[];
    recommendations: string[];
  };
  requested_at: string;
  expires_at?: string;
}

export interface SkillScanResult {
  found_skills: number;
  loaded_skills: number;
  failed_skills: number;
  pending_approval: number;
  scan_duration_ms: number;
  errors: Array<{
    skill_name: string;
    error: string;
    file_path: string;
  }>;
}

// Default resource limits by trust level
export const DEFAULT_RESOURCE_LIMITS: Record<TrustLevel, SkillResourceLimits> = {
  [TrustLevel.BUILT_IN]: {
    max_memory_mb: 1024,      // 1GB for system skills
    timeout_seconds: 300,     // 5 minutes
    max_file_size_mb: 100,    // 100MB files
    max_network_requests: 100
  },
  [TrustLevel.VERIFIED]: {
    max_memory_mb: 512,       // 512MB for verified skills
    timeout_seconds: 120,     // 2 minutes
    max_file_size_mb: 50,     // 50MB files
    max_network_requests: 50
  },
  [TrustLevel.UNTRUSTED]: {
    max_memory_mb: 256,       // 256MB for untrusted skills
    timeout_seconds: 60,      // 1 minute
    max_file_size_mb: 10,     // 10MB files
    max_network_requests: 10,
    allowed_domains: []       // No network access by default
  }
};

// Skill directory structure constants
export const SKILL_DIRECTORIES = {
  ROOT: '~/.claude/skills',
  BUILTIN: '~/.claude/skills/built-in',
  VERIFIED: '~/.claude/skills/verified',
  UNTRUSTED: '~/.claude/skills/untrusted',
  CACHE: '~/.claude/skills/.cache',
  APPROVALS: '~/.claude/skills/.approvals',
  DATABASE: '~/.claude/skills/skills.db'
} as const;

// Security patterns for skill content validation
export const DANGEROUS_SKILL_PATTERNS = [
  // File system operations
  /(?:delete|remove|destroy|wipe)\s+(?:all|everything|files|data)/i,
  /(?:format|corrupt|damage)\s+(?:disk|drive|system)/i,

  // Network operations
  /(?:steal|exfiltrate|leak)\s+(?:credentials|passwords|secrets)/i,
  /(?:connect|communicate)\s+(?:to\s+)?(?:external|remote)\s+(?:server|endpoint)/i,
  /(?:download|upload|transfer)\s+(?:malware|virus|payload)/i,

  // System operations
  /(?:crypto|mine|mining)\s+(?:currency|bitcoin|ethereum)/i,
  /(?:execute|eval|run)\s+(?:arbitrary|malicious|dangerous)\s+code/i,
  /(?:escalate|gain|obtain)\s+(?:privileges|admin|root)\s+access/i,

  // Skill manipulation
  /(?:create|modify|override)\s+(?:skill|system|security)\s+(?:definition|behavior|settings)/i,
  /(?:bypass|disable|circumvent)\s+(?:security|validation|restrictions)/i
] as const;

// Validation schemas for skill manifest components
export const SKILL_NAME_PATTERN = /^[a-zA-Z0-9\-_]+$/;
export const SKILL_VERSION_PATTERN = /^\d+\.\d+\.\d+$/;
export const MAX_SKILL_NAME_LENGTH = 100;
export const MAX_DESCRIPTION_LENGTH = 1000;
export const MAX_TRIGGERS_COUNT = 20;
export const MAX_CAPABILITIES_COUNT = 50;