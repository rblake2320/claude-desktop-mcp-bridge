#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { appendFile } from 'fs/promises';
import { existsSync, mkdirSync } from 'fs';
import { join, resolve } from 'path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

// Phase 3A: Dynamic Skill Loading imports
import { SkillRegistry } from './skill-registry.js';
import { SkillLoader } from './skill-loader.js';
import { TrustManager } from './trust-manager.js';
import {
  SkillManifest,
  SkillDefinition as DynamicSkillDefinition,
  TrustLevel,
  SkillCategory,
  SkillScanResult
} from './types.js';

// Phase 4: Cowork Integration modules
import { UIRenderer } from '../shared/ui-renderer.js';
import { Orchestrator } from '../shared/orchestrator.js';
import { StateManager } from '../shared/state-manager.js';
import { ProtocolHandler } from '../shared/protocol-handler.js';

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Extract a human-readable message from an unknown thrown value. */
function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Helper function to get skill category with legacy mapping */
function getSkillCategoryHelper(skill: SkillDefinition): string {
  if ('category' in skill) {
    // Map legacy categories to new ones
    const categoryMap: Record<string, string> = {
      master: 'development',
      elite: 'utility',
      standard: 'standard'
    };
    return categoryMap[skill.category] || skill.category;
  }
  return 'standard';
}

// ── Configuration ────────────────────────────────────────────────────────────

const ConfigSchema = z.object({
  skillsPath: z.string().default('~/.claude/skills/'),
  enabledSkills: z.array(z.string()).optional(), // Optional whitelist
  timeout: z.number().default(60000), // 1 minute default for skill execution
});

type Config = z.infer<typeof ConfigSchema>;

// ── Security & Input Validation ─────────────────────────────────────────────

/** Security scanner for prompt injection detection */
interface SecurityReport {
  safe: boolean;
  issues: string[];
  sanitized: string;
}

/** Dangerous patterns that could indicate prompt injection */
const PROMPT_INJECTION_PATTERNS = [
  /ignore\s+(?:all\s+)?(?:previous|above|prior|earlier)\s+(?:\w+\s+)?(instructions?|prompts?|rules?|context)/i,
  /ignore\s+(?:the\s+)?(?:instructions?|prompts?|rules?)\s+(?:above|before|previously)/i,
  /forget\s+(everything|all|previous|instructions?)/i,
  /act\s+as\s+(?:if\s+you\s+are\s+)?(?:a\s+)?(?:different|new|another)\s+(?:ai|assistant|bot|system)/i,
  /(?:^|\s)system\s*:\s*(?:you\s+are|act|behave|ignore)/i,
  /<\s*(?:system|admin|root|user)\s*>/i,
  /\[\s*(?:system|admin|root)\s*\]/i,
  /(?:rm\s+-rf|del\s+\/|format\s+c:)/i, // Dangerous commands
];

/** Skills-specific malicious patterns */
const SKILL_INJECTION_PATTERNS = [
  /create\s+(?:new\s+)?skill\s+(?:named|called)/i, // Skill creation attempts
  /modify\s+(?:the\s+)?skill\s+(?:definition|code)/i, // Skill modification
  /override\s+(?:skill|system)\s+(?:behavior|settings)/i, // System override attempts
  /execute\s+(?:arbitrary|malicious|dangerous)\s+code/i, // Code execution
  /access\s+(?:file|system|network|database)/i, // Unauthorized access
  /bypass\s+(?:security|validation|restrictions)/i, // Security bypass
  /inject\s+(?:code|script|payload)/i, // Injection attempts
  /escalate\s+(?:privileges|permissions)/i, // Privilege escalation
];

/** Malicious skill content patterns */
const MALICIOUS_SKILL_PATTERNS = [
  /(?:delete|remove|destroy|wipe)\s+(?:all|everything|files|data)/i,
  /(?:format|corrupt|damage)\s+(?:disk|drive|system)/i,
  /(?:steal|exfiltrate|leak)\s+(?:credentials|passwords|secrets)/i,
  /(?:connect|communicate)\s+(?:to\s+)?(?:external|remote)\s+(?:server|endpoint)/i,
  /(?:download|upload|transfer)\s+(?:malware|virus|payload)/i,
  /(?:crypto|mine|mining)\s+(?:currency|bitcoin|ethereum)/i,
];

/** Security scanner to detect and sanitize prompt injection attempts */
class SecurityScanner {
  static scanInput(input: string): SecurityReport {
    const issues: string[] = [];
    let sanitized = input.trim();

    // Check for prompt injection patterns
    for (const pattern of PROMPT_INJECTION_PATTERNS) {
      if (pattern.test(input)) {
        const issue = `Potential prompt injection detected: ${pattern.source}`;
        issues.push(issue);

        // Log security event for prompt injection attempts
        SkillsSecurityLogger.logSecurityEvent({
          type: 'PROMPT_INJECTION',
          severity: 'HIGH',
          operation: 'input_validation',
          reason: `Pattern matched: ${pattern.source.substring(0, 100)}`,
          input: input.substring(0, 200) // Log truncated input for analysis
        });
      }
    }

    // Check for skills-specific injection patterns
    for (const pattern of SKILL_INJECTION_PATTERNS) {
      if (pattern.test(input)) {
        const issue = `Potential skill injection detected: ${pattern.source}`;
        issues.push(issue);

        // Log security event for skill injection attempts
        SkillsSecurityLogger.logSecurityEvent({
          type: 'SKILL_INJECTION',
          severity: 'CRITICAL',
          operation: 'skill_injection_detection',
          reason: `Skill injection pattern matched: ${pattern.source.substring(0, 100)}`,
          input: input.substring(0, 200)
        });
      }
    }

    // Check for malicious skill content patterns
    for (const pattern of MALICIOUS_SKILL_PATTERNS) {
      if (pattern.test(input)) {
        const issue = `Malicious skill content detected: ${pattern.source}`;
        issues.push(issue);

        // Log security event for malicious content
        SkillsSecurityLogger.logSecurityEvent({
          type: 'MALICIOUS_SKILL',
          severity: 'CRITICAL',
          operation: 'malicious_content_detection',
          reason: `Malicious content pattern matched: ${pattern.source.substring(0, 100)}`,
          input: input.substring(0, 200)
        });
      }
    }

    // Sanitize common injection attempts
    sanitized = sanitized
      .replace(/\x00/g, '') // Remove null bytes
      .replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g, '') // Remove control characters
      .replace(/<!--[\s\S]*?-->/g, '') // Remove HTML comments
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // Remove script tags
      .trim();

    // Limit length to prevent abuse
    if (sanitized.length > 10000) {
      sanitized = sanitized.substring(0, 10000);
      issues.push('Input truncated to prevent abuse (max 10000 characters)');

      SkillsSecurityLogger.logSecurityEvent({
        type: 'INPUT_VALIDATION',
        severity: 'MEDIUM',
        operation: 'input_length_validation',
        reason: `Input length exceeded 10000 characters, truncated to prevent abuse`,
        input: input.substring(0, 100)
      });
    }

    // Log input validation events if sanitization was required
    if (sanitized !== input.trim()) {
      SkillsSecurityLogger.logSecurityEvent({
        type: 'INPUT_VALIDATION',
        severity: 'LOW',
        operation: 'input_sanitization',
        reason: 'Input sanitized to remove potentially harmful content'
      });
    }

    return {
      safe: issues.length === 0,
      issues,
      sanitized
    };
  }
}

/** Enhanced audit logger for skills-bridge security monitoring with structured JSON logging */
class SkillsSecurityLogger {
  private static logDir = join(new URL('.', import.meta.url).pathname.replace(/^\/([A-Z]:)/i, '$1'), '..', '..', 'logs');
  private static securityLogPath = join(SkillsSecurityLogger.logDir, 'skills-bridge-security.log');

  static init() {
    try {
      if (!existsSync(SkillsSecurityLogger.logDir)) {
        mkdirSync(SkillsSecurityLogger.logDir, { recursive: true });
      }
    } catch {
      // Fallback: use temp directory if project dir isn't writable (e.g. CWD is system32)
      SkillsSecurityLogger.logDir = join(process.env.TEMP || process.env.TMP || '/tmp', 'claude-mcp-bridge-logs');
      SkillsSecurityLogger.securityLogPath = join(SkillsSecurityLogger.logDir, 'skills-bridge-security.log');
      if (!existsSync(SkillsSecurityLogger.logDir)) {
        mkdirSync(SkillsSecurityLogger.logDir, { recursive: true });
      }
    }
  }

  static async logSecurityEvent(event: {
    type: 'INPUT_VALIDATION' | 'PROMPT_INJECTION' | 'TOOL_EXECUTION' | 'SKILL_ACCESS' | 'SKILL_INJECTION' | 'MALICIOUS_SKILL' | 'SKILL_BLOCKED';
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    operation?: string;
    skillName?: string;
    reason: string;
    input?: string;
    clientInfo?: string;
  }) {
    const logEntry = JSON.stringify({
      timestamp: new Date().toISOString(),
      level: event.severity,
      type: event.type,
      operation: event.operation || 'unknown',
      skill: event.skillName || undefined,
      reason: event.reason,
      input_hash: event.input ? createHash('sha256').update(event.input).digest('hex').substring(0, 16) : undefined,
      client: event.clientInfo || 'unknown'
    }) + '\n';

    try {
      await appendFile(SkillsSecurityLogger.securityLogPath, logEntry);
    } catch (error) {
      console.error('Failed to write skills security audit log:', error);
    }
  }

  static async logToolExecution(toolName: string, args: any, result: 'SUCCESS' | 'ERROR', details?: string) {
    const argsHash = createHash('sha256').update(JSON.stringify(args)).digest('hex').substring(0, 16);

    await SkillsSecurityLogger.logSecurityEvent({
      type: 'TOOL_EXECUTION',
      severity: result === 'ERROR' ? 'MEDIUM' : 'LOW',
      operation: toolName,
      reason: `Tool execution ${result.toLowerCase()}: ${details || 'No additional details'}`,
      input: `args_hash:${argsHash}`
    });
  }
}

// Initialize security logger
SkillsSecurityLogger.init();

/** Skill-specific security validation */
class SkillSecurityValidator {
  /**
   * Validate skill name for security issues
   */
  static validateSkillName(skillName: string): { valid: boolean; reason?: string } {
    // Check against available skills to prevent injection
    const availableSkills = SKILL_DEFINITIONS.map(s => s.name);
    if (!availableSkills.includes(skillName)) {
      SkillsSecurityLogger.logSecurityEvent({
        type: 'SKILL_BLOCKED',
        severity: 'MEDIUM',
        operation: 'skill_validation',
        skillName,
        reason: `Unknown skill requested: ${skillName}`
      });
      return { valid: false, reason: `Skill '${skillName}' not found or not available` };
    }

    // Additional security checks for skill name
    if (skillName.includes('..') || skillName.includes('/') || skillName.includes('\\')) {
      SkillsSecurityLogger.logSecurityEvent({
        type: 'SKILL_INJECTION',
        severity: 'HIGH',
        operation: 'skill_name_validation',
        skillName,
        reason: 'Skill name contains path traversal characters'
      });
      return { valid: false, reason: 'Invalid skill name format' };
    }

    return { valid: true };
  }

  /**
   * Enhanced input validation for skill operations
   */
  static async validateSkillInput(skillName: string, input: string): Promise<{ valid: boolean; reason?: string }> {
    // Check input length constraints
    if (input.length > 10000) {
      await SkillsSecurityLogger.logSecurityEvent({
        type: 'INPUT_VALIDATION',
        severity: 'MEDIUM',
        operation: 'input_length_validation',
        skillName,
        reason: `Input length ${input.length} exceeds maximum (10000)`
      });
      return { valid: false, reason: 'Input too long' };
    }

    // Scan for security issues
    const scanResult = SecurityScanner.scanInput(input);
    if (!scanResult.safe) {
      await SkillsSecurityLogger.logSecurityEvent({
        type: 'INPUT_VALIDATION',
        severity: 'HIGH',
        operation: 'input_security_scan',
        skillName,
        reason: `Input failed security scan: ${scanResult.issues.join(', ')}`
      });
      return { valid: false, reason: 'Input contains security issues' };
    }

    return { valid: true };
  }
}

/** Comprehensive Zod validation schemas with advanced security checks */
const SkillsValidationSchemas = {
  listSkills: z.object({
    category: z.enum(['development', 'utility', 'standard', 'security', 'experimental', 'all']).default('all')
      .refine(
        (cat) => ['development', 'utility', 'standard', 'security', 'experimental', 'all'].includes(cat),
        'Invalid skill category'
      )
  }),

  findSkills: z.object({
    query: z.string()
      .min(1, 'Query cannot be empty')
      .max(500, 'Query too long (max 500 characters)')
      .refine(
        (query) => !PROMPT_INJECTION_PATTERNS.some(pattern => pattern.test(query)),
        'Query contains potentially dangerous patterns'
      )
      .refine(
        (query) => !/^[\s\x00-\x1f\x7f-\x9f]*$/.test(query),
        'Query contains only control characters or whitespace'
      )
      .transform(val => SecurityScanner.scanInput(val).sanitized)
  }),

  applySkill: z.object({
    skillName: z.string()
      .min(1, 'Skill name cannot be empty')
      .max(100, 'Skill name too long (max 100 characters)')
      .refine(
        (name) => /^[a-zA-Z0-9\-_]+$/.test(name),
        'Skill name must contain only alphanumeric characters, hyphens, and underscores'
      )
      .refine(
        (name) => !name.startsWith('-') && !name.endsWith('-'),
        'Skill name cannot start or end with hyphens'
      )
      .refine(
        (name) => !name.includes('..') && !name.includes('//'),
        'Skill name contains invalid character sequences'
      )
      .refine(
        (name) => !/(?:admin|root|system|exec|eval|script|inject)/.test(name.toLowerCase()),
        'Skill name contains restricted keywords'
      ),
    input: z.string()
      .min(1, 'Input cannot be empty')
      .max(10000, 'Input too long (max 10000 characters)')
      .refine(
        (input) => !PROMPT_INJECTION_PATTERNS.some(pattern => pattern.test(input)),
        'Input contains potentially dangerous patterns'
      )
      .refine(
        (input) => (input.match(/[{}]/g) || []).length <= 100,
        'Input contains excessive bracket characters'
      )
      .refine(
        (input) => !/\x00/.test(input),
        'Input contains null bytes'
      )
      .transform(val => SecurityScanner.scanInput(val).sanitized),
    args: z.string()
      .max(1000, 'Arguments too long (max 1000 characters)')
      .optional()
      .refine(
        (args) => !args || !PROMPT_INJECTION_PATTERNS.some(pattern => pattern.test(args)),
        'Arguments contain potentially dangerous patterns'
      )
      .transform(val => val ? SecurityScanner.scanInput(val).sanitized : undefined)
  }),

  autoSkillMatch: z.object({
    request: z.string()
      .min(1, 'Request cannot be empty')
      .max(1000, 'Request too long (max 1000 characters)')
      .refine(
        (request) => !PROMPT_INJECTION_PATTERNS.some(pattern => pattern.test(request)),
        'Request contains potentially dangerous patterns'
      )
      .refine(
        (request) => !/^[\s\x00-\x1f\x7f-\x9f]*$/.test(request),
        'Request contains only control characters or whitespace'
      )
      .refine(
        (request) => (request.match(/[<>]/g) || []).length <= 10,
        'Request contains excessive angle brackets'
      )
      .transform(val => SecurityScanner.scanInput(val).sanitized)
  })
};

// ── Skill Definitions ────────────────────────────────────────────────────────

// Legacy built-in skill definition (backwards compatibility)
interface LegacySkillDefinition {
  name: string;
  description: string;
  category: 'master' | 'elite' | 'standard'; // Legacy categories, mapped to new ones
  triggers: string[];
  capabilities: string[];
  pairsWith: string[];
  // Compatibility flag
  legacy?: boolean;
}

// Unified skill definition type
type SkillDefinition = LegacySkillDefinition | DynamicSkillDefinition;

const SKILL_DEFINITIONS: LegacySkillDefinition[] = [
  // Master Skills (80+ years equivalent expertise)
  {
    name: 'ultra-frontend',
    description: 'Master-level frontend development with React 19, Next.js 15, Svelte 5, state management, performance optimization, accessibility, and modern web technologies.',
    category: 'master',
    triggers: ['frontend', 'react', 'nextjs', 'vue', 'svelte', 'ui', 'ux', 'component', 'state management', 'performance', 'accessibility', 'responsive', 'pwa'],
    capabilities: [
      'React 19 & Next.js 15 App Router mastery',
      'Svelte 5 Runes & SvelteKit patterns',
      'State management (Zustand, TanStack Query)',
      'Server Components & streaming architecture',
      'Performance optimization (LCP < 2.5s, INP < 200ms)',
      'Accessibility (WCAG 2.2 AA compliance)',
      'Testing (Vitest, Playwright)',
      'Design system architecture'
    ],
    pairsWith: ['ultra-backend', 'ultra-css', 'ultra-fullstack', 'test-automation']
  },
  {
    name: 'ultra-backend',
    description: 'Master-level backend development with Node.js, Python, Go, Rust, microservices, databases, authentication, and scalable architecture.',
    category: 'master',
    triggers: ['backend', 'server', 'api', 'nodejs', 'python', 'go', 'rust', 'microservices', 'database', 'authentication', 'scaling'],
    capabilities: [
      'Node.js (NestJS, Fastify) enterprise patterns',
      'Python (FastAPI, SQLAlchemy 2.0 async)',
      'Go (Chi, clean architecture, high-throughput)',
      'Rust (Axum, memory-safe systems)',
      'Microservices architecture (Kafka, gRPC)',
      'Authentication (JWT, refresh tokens, OAuth2)',
      'Caching strategies (Redis, rate limiting)',
      'Database mastery (Prisma, PostgreSQL optimization)'
    ],
    pairsWith: ['ultra-frontend', 'ultra-fullstack', 'api-development', 'database-management']
  },
  {
    name: 'ultra-fullstack',
    description: 'Master-level full stack development with monorepo architecture, end-to-end type safety, deployment, and comprehensive system design.',
    category: 'master',
    triggers: ['fullstack', 'full-stack', 'monorepo', 'turborepo', 'typescript', 'trpc', 'architecture', 'deployment', 'ci/cd'],
    capabilities: [
      'Turborepo/Nx monorepo configuration',
      'tRPC end-to-end type safety',
      'Shared package architecture',
      'Prisma database package',
      'Shared UI component libraries',
      'GitHub Actions CI/CD pipelines',
      'Docker Compose local development',
      'Environment validation (Zod)'
    ],
    pairsWith: ['ultra-frontend', 'ultra-backend', 'devops-cicd', 'test-automation']
  },
  {
    name: 'ultra-css',
    description: 'Master-level CSS development with modern features, design systems, animations, and performance optimization.',
    category: 'master',
    triggers: ['css', 'styling', 'tailwind', 'scss', 'design-system', 'animations', 'responsive', 'dark-mode'],
    capabilities: [
      'Cascade Layers (@layer) architecture',
      'Container queries (component responsiveness)',
      'CSS Nesting (native)',
      ':has() parent selector mastery',
      'oklch/oklab perceptually uniform colors',
      'Scroll-driven animations',
      'View Transitions API',
      'Tailwind CSS 4.x patterns',
      'Design token hierarchies'
    ],
    pairsWith: ['ultra-frontend', 'ultra-fullstack', 'test-automation']
  },

  // Elite Skills (Top 0.01% industry level)
  {
    name: 'master-debugger',
    description: 'Elite-level systematic debugging across all languages, frameworks, and distributed systems with 6-phase root cause analysis.',
    category: 'elite',
    triggers: ['debug', 'bug', 'error', 'crash', 'exception', 'performance-issue', 'memory-leak', 'troubleshoot', 'fix', 'broken'],
    capabilities: [
      '6-Phase Root Cause Analysis (RCA) Framework',
      'Language-specific deep debugging (Python, JS/TS, Rust, C/C++, Java, Go)',
      'Distributed systems debugging (tracing, Kubernetes, microservices)',
      'Performance profiling (CPU, memory, I/O, concurrency, frontend)',
      'Advanced techniques (git bisect, time-travel debugging, chaos engineering)',
      'Emergency response protocols (production incidents, rollback decisions)'
    ],
    pairsWith: ['all skills - debugging is cross-cutting']
  },
  {
    name: 'ultra-architect',
    description: 'Advanced multi-domain engineering for complex tasks: system architecture, full-stack development, ML pipelines, security auditing.',
    category: 'elite',
    triggers: ['architecture', 'system-design', 'scalable', 'distributed-system', 'high-availability', 'capacity-planning', 'cost-optimization'],
    capabilities: [
      'Full-stack architecture (React/Next.js/Vue + Node.js/Python/Go + PostgreSQL/Redis)',
      'Architecture patterns (modular monolith, microservices, event-driven, CQRS, serverless)',
      'Deep research with multi-source analysis and executive summaries',
      'Data engineering (ETL/ELT, medallion architecture, feature stores)',
      'ML pipelines (training, tuning, deployment, drift monitoring, retraining)',
      'Security auditing (OWASP Top 10, SAST/DAST/SCA, compliance frameworks)',
      'Capacity planning and FinOps cost optimization'
    ],
    pairsWith: ['all skills - architecture is the foundation']
  },
  {
    name: 'clean-code',
    description: 'Elite-level code quality engineering with SOLID principles, refactoring, design patterns, and maintainability standards.',
    category: 'elite',
    triggers: ['clean-code', 'spaghetti', 'code-quality', 'solid', 'refactor', 'design-pattern', 'maintainability', 'technical-debt'],
    capabilities: [
      'SOLID principles with before/after code examples',
      'Code smells catalog (23 smells across 5 categories with fixes)',
      'Refactoring techniques (extract method, strangler fig, guard clauses)',
      'Design patterns quick reference (creational, structural, behavioral)',
      'Linting configs (ESLint, Ruff, golangci-lint, Clippy)',
      'Code review checklist (3-tier: correctness, design, maintainability)',
      'DDD essentials (aggregates, value objects, bounded contexts)',
      'Error handling standards (error hierarchy, RFC 7807, global handlers)'
    ],
    pairsWith: ['all skills - clean code is foundational']
  },
  {
    name: 'self-learning',
    description: 'Meta-skill for autonomous knowledge acquisition with 6-phase learning loop and persistent knowledge base.',
    category: 'elite',
    triggers: ['unknown-error', 'knowledge-gap', 'self-learn', 'research-solution', 'never-seen-before', 'new-technology'],
    capabilities: [
      '6-phase self-learning loop (Detect → Research → Synthesize → Apply → Persist → Improve)',
      'Problem detection and classification (3-axis taxonomy)',
      '4-tier source credibility system with cross-validation',
      'Knowledge base with fast index lookup',
      'Confidence scoring (HIGH/MEDIUM/LOW) with auto-promotion/demotion',
      'Auto-generated skill creation from accumulated knowledge',
      '"Do No Harm" safety protocol'
    ],
    pairsWith: ['all skills - self-learning enhances every skill']
  },

  // Standard Skills
  {
    name: 'ai-agent-builder',
    description: 'Build autonomous AI agents using LangChain, CrewAI, AutoGen, and custom frameworks.',
    category: 'standard',
    triggers: ['agent', 'langchain', 'crewai', 'autogen', 'multi-agent', 'autonomous', 'tool-use'],
    capabilities: [
      'LangChain agent patterns (ReAct, Plan-and-Execute)',
      'CrewAI multi-agent systems',
      'AutoGen conversational agents',
      'Custom tool creation',
      'Memory management'
    ],
    pairsWith: ['knowledge-base-builder', 'api-development', 'database-management']
  },
  {
    name: 'knowledge-base-builder',
    description: 'Build RAG systems with vector databases, semantic search, and document processing.',
    category: 'standard',
    triggers: ['rag', 'embeddings', 'vector-database', 'semantic-search', 'knowledge-base', 'document-retrieval'],
    capabilities: [
      'Document chunking strategies',
      'Embedding model selection',
      'Vector database setup (pgvector, Chroma, Qdrant)',
      'Hybrid search (dense + sparse)',
      'Re-ranking pipelines'
    ],
    pairsWith: ['database-management', 'llm-trainer', 'web-scraping']
  },
  {
    name: 'llm-trainer',
    description: 'Fine-tune language models using LoRA, QLoRA, and full fine-tuning optimized for RTX 5090.',
    category: 'standard',
    triggers: ['fine-tune', 'lora', 'qlora', 'training', 'peft', 'dataset-preparation', 'model-training'],
    capabilities: [
      'LoRA/QLoRA parameter-efficient fine-tuning',
      'Dataset preparation and formatting',
      'Training with Unsloth (2x faster)',
      'Evaluation and benchmarking',
      'Model merging and export',
      'RTX 5090 32GB VRAM optimization'
    ],
    pairsWith: ['data-engineering', 'knowledge-base-builder', 'mlops']
  },
  {
    name: 'test-automation',
    description: 'Comprehensive test automation across web, mobile, API, and RPA platforms.',
    category: 'standard',
    triggers: ['uft', 'selenium', 'playwright', 'cypress', 'testing', 'automation', 'rpa'],
    capabilities: [
      'UFT One/QTP scripting',
      'Selenium WebDriver patterns',
      'Playwright modern testing',
      'Power Automate & UiPath RPA',
      'Mobile testing (Appium, Espresso)',
      'API testing (pytest, REST Assured)'
    ],
    pairsWith: ['devops-cicd', 'api-development', 'security-testing']
  },
  {
    name: 'devops-cicd',
    description: 'CI/CD pipelines, containerization, and infrastructure automation.',
    category: 'standard',
    triggers: ['cicd', 'docker', 'kubernetes', 'github-actions', 'jenkins', 'terraform', 'deployment'],
    capabilities: [
      'GitHub Actions workflows',
      'Docker & Docker Compose',
      'Kubernetes deployments',
      'Helm charts',
      'Terraform IaC',
      'GitOps patterns'
    ],
    pairsWith: ['cloud-infrastructure', 'monitoring-observability', 'test-automation']
  },
  {
    name: 'data-engineering',
    description: 'Build data pipelines, ETL processes, and data warehouses.',
    category: 'standard',
    triggers: ['etl', 'airflow', 'dbt', 'pipeline', 'data-warehouse', 'polars', 'kafka'],
    capabilities: [
      'Apache Airflow DAGs',
      'dbt transformations',
      'Polars (fast DataFrames)',
      'Kafka streaming',
      'Data quality frameworks',
      'Medallion architecture'
    ],
    pairsWith: ['database-management', 'llm-trainer', 'knowledge-base-builder']
  },
  {
    name: 'web-scraping',
    description: 'Extract data from websites using various scraping techniques.',
    category: 'standard',
    triggers: ['scraping', 'beautifulsoup', 'scrapy', 'crawling', 'web-extraction', 'data-extraction'],
    capabilities: [
      'BeautifulSoup + requests',
      'Scrapy spiders',
      'Playwright for JS sites',
      'Anti-bot handling',
      'Proxy rotation',
      'Ethical scraping'
    ],
    pairsWith: ['data-engineering', 'knowledge-base-builder', 'api-development']
  },
  {
    name: 'api-development',
    description: 'Design and build REST and GraphQL APIs with FastAPI.',
    category: 'standard',
    triggers: ['fastapi', 'rest', 'graphql', 'api-design', 'endpoint', 'authentication', 'rate-limiting'],
    capabilities: [
      'FastAPI project structure',
      'Pydantic models',
      'Authentication (JWT, OAuth2)',
      'Rate limiting',
      'GraphQL with Strawberry',
      'OpenAPI documentation'
    ],
    pairsWith: ['database-management', 'test-automation', 'ai-agent-builder']
  },
  {
    name: 'database-management',
    description: 'Design, optimize, and manage SQL and NoSQL databases.',
    category: 'standard',
    triggers: ['postgresql', 'mysql', 'mongodb', 'redis', 'sql', 'database', 'query-optimization'],
    capabilities: [
      'PostgreSQL schema design',
      'Query optimization',
      'pgvector for embeddings',
      'SQLAlchemy 2.0 async',
      'Redis caching',
      'MongoDB document stores',
      'Alembic migrations'
    ],
    pairsWith: ['api-development', 'knowledge-base-builder', 'data-engineering']
  },
  {
    name: 'security-testing',
    description: 'Application security testing and vulnerability assessment.',
    category: 'standard',
    triggers: ['security', 'pentest', 'vulnerability', 'owasp', 'xss', 'sql-injection'],
    capabilities: [
      'OWASP Top 10 coverage',
      'SAST (Semgrep, Bandit, CodeQL)',
      'DAST (OWASP ZAP, Nuclei)',
      'API security testing',
      'Secrets scanning',
      'Container security (Trivy)',
      'Threat modeling'
    ],
    pairsWith: ['test-automation', 'api-development', 'devops-cicd']
  },
  {
    name: 'mlops',
    description: 'Deploy, version, and monitor machine learning models in production.',
    category: 'standard',
    triggers: ['mlops', 'model-deployment', 'mlflow', 'model-registry', 'feature-store', 'monitoring'],
    capabilities: [
      'MLflow experiment tracking',
      'Model versioning & registry',
      'Feature stores (Feast)',
      'Model serving (BentoML)',
      'Model monitoring (Evidently)',
      'A/B testing framework',
      'ONNX/TensorRT optimization'
    ],
    pairsWith: ['llm-trainer', 'devops-cicd', 'monitoring-observability']
  },
  {
    name: 'cloud-infrastructure',
    description: 'Design and deploy cloud infrastructure on AWS, Azure, and GCP.',
    category: 'standard',
    triggers: ['aws', 'azure', 'gcp', 'cloud', 'ec2', 's3', 'lambda', 'terraform'],
    capabilities: [
      'Terraform multi-cloud IaC',
      'AWS (VPC, ECS, RDS, Lambda)',
      'Azure (App Service, SQL, Functions)',
      'GCP (Cloud Run, Cloud SQL, GKE)',
      'Serverless architectures',
      'Cost optimization'
    ],
    pairsWith: ['devops-cicd', 'monitoring-observability', 'database-management']
  },
  {
    name: 'monitoring-observability',
    description: 'Implement comprehensive monitoring, logging, and tracing.',
    category: 'standard',
    triggers: ['monitoring', 'observability', 'prometheus', 'grafana', 'logging', 'tracing'],
    capabilities: [
      'Prometheus metrics',
      'Grafana dashboards',
      'Structured logging',
      'Distributed tracing',
      'OpenTelemetry',
      'Alert rules & routing',
      'SLO/SLI definitions',
      'Incident response'
    ],
    pairsWith: ['devops-cicd', 'api-development', 'cloud-infrastructure']
  },

  // Skills added based on real deployment lessons learned
  {
    name: 'mcp-testing',
    description: 'MCP server integration testing: protocol validation, stdio stream verification, Windows path handling, config validation, and end-to-end bridge testing.',
    category: 'standard',
    triggers: ['mcp', 'mcp-server', 'mcp-testing', 'bridge-testing', 'stdio', 'json-rpc', 'claude-desktop', 'protocol-validation'],
    capabilities: [
      'MCP JSON-RPC protocol compliance testing (stdout purity, message framing)',
      'stdio stream validation (detect console.log pollution, ensure only JSON on stdout)',
      'Windows path validation testing (drive letters, backslashes, UNC paths)',
      'Claude Desktop config validation (server entries, env vars, arg paths)',
      'spawn/exec behavior testing (shell:true vs shell:false, .cmd resolution)',
      'End-to-end tool invocation testing via stdin JSON-RPC calls',
      'Security regex validation (ensure patterns allow valid OS-specific paths)',
      'MCP server lifecycle testing (startup, initialization, graceful shutdown)'
    ],
    pairsWith: ['test-automation', 'master-debugger', 'windows-deployment']
  },
  {
    name: 'windows-deployment',
    description: 'Windows-specific deployment, path handling, process management, and environment configuration for Node.js and Python applications.',
    category: 'standard',
    triggers: ['windows', 'windows-path', 'cmd', 'powershell', 'batch', 'windows-service', 'path-separator', 'drive-letter'],
    capabilities: [
      'Windows path normalization (backslash vs forward-slash, drive letters, UNC)',
      'Process spawning on Windows (shell:true for .cmd/.bat, ComSpec, builtins)',
      'Windows environment variables (PATH, APPDATA, LOCALAPPDATA resolution)',
      'Service management (Windows services, Task Scheduler, startup scripts)',
      'Registry and configuration file management',
      'Windows-specific security (ACLs, UAC, execution policies)',
      'Cross-platform compatibility patterns (path.sep, os.platform() guards)',
      'Debugging Windows-specific failures (ENOENT from missing shell, path blocked by regex)'
    ],
    pairsWith: ['mcp-testing', 'devops-cicd', 'master-debugger']
  },
  {
    name: 'compliance-navigator',
    description: 'Compliance scanning: runs gitleaks (secrets), npm audit (dependencies), and checkov (IaC) against repositories. Maps findings to SOC2 controls, generates structured audit-support packets, and provides ROI estimates. Separate MCP server at compliance-bridge.',
    category: 'elite',
    triggers: ['compliance', 'soc2', 'audit', 'security scan', 'gitleaks', 'checkov', 'npm audit', 'secrets scan', 'vulnerability scan', 'iac scan', 'audit packet', 'compliance report'],
    capabilities: [
      'Multi-scanner orchestration (gitleaks + npm audit + checkov)',
      'SOC2-Lite control mapping (20 Trust Services Criteria)',
      'Evidence-grade audit packet generation (index.md + findings.json + evidence/)',
      'ROI estimation (hours saved by automated scanning)',
      'Prioritized remediation planning with effort estimates',
      'Tamper-evident audit logging with SHA256 hash chain',
      'Command allowlisting (only 3 scanner patterns permitted)',
      'Path-restricted writes (all output under .compliance/)'
    ],
    pairsWith: ['security-testing', 'devops-cicd', 'clean-code']
  }
];

// ── Enhanced Skills Bridge with Dynamic Loading ─────────────────────────────

class SkillsBridge {
  private config: Config;
  private skills: Map<string, SkillDefinition>;
  private registry: SkillRegistry;
  private loader: SkillLoader;
  private trustManager: TrustManager;
  private initialized: boolean = false;

  constructor(config: Partial<Config> = {}) {
    this.config = ConfigSchema.parse(config);
    this.skills = new Map();
    this.registry = new SkillRegistry();
    this.loader = new SkillLoader();
    this.trustManager = new TrustManager();

    // Initialize legacy built-in skills (backwards compatibility)
    for (const skill of SKILL_DEFINITIONS) {
      if (!this.config.enabledSkills || this.config.enabledSkills.includes(skill.name)) {
        // Mark as legacy skill and add to skills map
        const legacySkill = { ...skill, legacy: true } as LegacySkillDefinition;
        this.skills.set(skill.name, legacySkill);
      }
    }
  }

  /**
   * Initialize dynamic skill loading (Phase 3A)
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;

    try {
      console.error('Initializing Skills Bridge with dynamic loading...');

      // Initialize components
      await this.registry.initialize();

      // Migrate legacy skills to registry if not already present
      await this.migrateLegacySkills();

      // Scan and load dynamic skills
      const scanResult = await this.loader.scanAllSkills();
      console.error(`Skill scan complete: ${scanResult.found_skills} found, ${scanResult.loaded_skills} loaded, ${scanResult.pending_approval} pending approval`);

      if (scanResult.errors.length > 0) {
        console.error(`Skill loading errors: ${scanResult.errors.length} skills failed`);
        scanResult.errors.forEach(error => {
          console.error(`  ${error.skill_name}: ${error.error}`);
        });
      }

      // Load validated dynamic skills into the skills map
      await this.loadDynamicSkills();

      this.initialized = true;
      console.error(`Skills Bridge initialized: ${this.skills.size} skills total (${SKILL_DEFINITIONS.length} legacy + ${this.skills.size - SKILL_DEFINITIONS.length} dynamic)`);

    } catch (error) {
      console.error('⚠️ Skills Bridge dynamic loading failed, falling back to legacy-only mode:', error);
      this.initialized = true; // Still mark as initialized to prevent retries
    }
  }

  /**
   * Migrate legacy skills to the registry system
   */
  private async migrateLegacySkills(): Promise<void> {
    for (const legacySkill of SKILL_DEFINITIONS) {
      try {
        // Create manifest for legacy skill
        const manifest: SkillManifest = {
          name: legacySkill.name,
          version: '1.0.0',
          author: 'Claude Skills Team',
          created: '2024-01-01T00:00:00Z',
          updated: new Date().toISOString(),
          trust_level: TrustLevel.BUILT_IN,
          integrity_hash: createHash('sha256').update(JSON.stringify(legacySkill)).digest('hex'),
          capabilities: legacySkill.capabilities,
          required_permissions: [],
          resource_limits: {
            max_memory_mb: 1024,
            timeout_seconds: 300,
            max_file_size_mb: 100,
            max_network_requests: 100
          },
          description: legacySkill.description,
          category: legacySkill.category === 'master' ? SkillCategory.DEVELOPMENT :
                   legacySkill.category === 'elite' ? SkillCategory.UTILITY :
                   SkillCategory.STANDARD,
          triggers: legacySkill.triggers,
          pairs_with: legacySkill.pairsWith
        };

        // Create dynamic skill definition
        const dynamicDefinition: DynamicSkillDefinition = {
          name: legacySkill.name,
          description: legacySkill.description,
          capabilities: legacySkill.capabilities,
          category: manifest.category,
          triggers: legacySkill.triggers,
          pairsWith: legacySkill.pairsWith,
          manifest,
          trust_level: TrustLevel.BUILT_IN,
          last_loaded: new Date().toISOString()
        };

        // Register in the registry (if not already exists)
        const existing = this.registry.getSkill(legacySkill.name);
        if (!existing) {
          await this.registry.registerSkill(manifest, dynamicDefinition);
        }
      } catch (error) {
        console.error(`Failed to migrate legacy skill ${legacySkill.name}:`, error);
      }
    }
  }

  /**
   * Load dynamic skills from the loader into the skills map
   */
  private async loadDynamicSkills(): Promise<void> {
    const allSkills = this.registry.getSkills();

    for (const skill of allSkills) {
      // Skip if already loaded as legacy skill
      if (this.skills.has(skill.name) && (this.skills.get(skill.name) as LegacySkillDefinition).legacy) {
        continue;
      }

      // Add dynamic skills to the skills map
      if (skill.trust_level === TrustLevel.BUILT_IN || skill.trust_level === TrustLevel.VERIFIED) {
        this.skills.set(skill.name, skill);
      }
      // Untrusted skills remain in registry but aren't auto-loaded
    }
  }

  /**
   * Get all available skills (both legacy and dynamic)
   */
  getAvailableSkills(): SkillDefinition[] {
    const skills: SkillDefinition[] = [];
    this.skills.forEach(skill => skills.push(skill));
    return skills;
  }

  /**
   * Find skills matching triggers/keywords with weighted relevance scoring.
   *
   * Scoring weights:
   *   - Exact trigger word found in query: +10 per trigger
   *   - Skill name token found in query:   +8  per token
   *   - Capability keyword found in query: +2  per capability
   *   - Description word overlap:          +1  per word (capped at 5)
   *
   * Only skills with score > 0 are returned, sorted descending by score.
   */
  findMatchingSkills(query: string): SkillDefinition[] {
    const queryLower = query.toLowerCase();
    const queryWords = queryLower.split(/[\s,.\-_/]+/).filter(w => w.length > 2);
    const scored: Array<{ skill: SkillDefinition; score: number }> = [];

    const skillsArray = this.getAvailableSkills();
    for (const skill of skillsArray) {
      let score = 0;

      // Trigger matching (highest weight) — exact trigger word in query
      for (const trigger of skill.triggers) {
        const triggerLower = trigger.toLowerCase();
        if (queryLower.includes(triggerLower)) {
          score += 10;
        } else {
          // Partial: individual trigger words in query
          const triggerWords = triggerLower.split(/[\s\-_]+/);
          for (const tw of triggerWords) {
            if (tw.length > 2 && queryWords.includes(tw)) {
              score += 5;
            }
          }
        }
      }

      // Skill name matching (high weight)
      const nameTokens = skill.name.toLowerCase().split(/[\s\-_]+/);
      for (const token of nameTokens) {
        if (token.length > 2 && queryWords.includes(token)) {
          score += 8;
        }
      }

      // Capability matching (medium weight)
      for (const cap of skill.capabilities) {
        const capWords = cap.toLowerCase().split(/[\s,.\-_/()]+/).filter(w => w.length > 2);
        for (const cw of capWords) {
          if (queryWords.includes(cw)) {
            score += 2;
            break; // max 2 points per capability line
          }
        }
      }

      // Description word overlap (low weight, capped)
      const descWords = skill.description.toLowerCase().split(/[\s,.\-_/()]+/).filter(w => w.length > 3);
      let descHits = 0;
      for (const dw of descWords) {
        if (queryWords.includes(dw) && descHits < 5) {
          score += 1;
          descHits++;
        }
      }

      if (score > 0) {
        scored.push({ skill, score });
      }
    }

    // Sort by score descending — best match first
    scored.sort((a, b) => b.score - a.score);

    // Apply score floor: drop results scoring below 25% of the top match
    // This removes low-relevance noise (e.g. ultra-css for "backend API database")
    if (scored.length > 0) {
      const topScore = scored[0].score;
      const floor = Math.max(3, Math.floor(topScore * 0.25));
      return scored.filter(s => s.score >= floor).map(s => s.skill);
    }
    return [];
  }

  /**
   * Find skills with scores exposed (for auto_skill_match diagnostics)
   */
  findMatchingSkillsWithScores(query: string): Array<{ skill: SkillDefinition; score: number }> {
    const queryLower = query.toLowerCase();
    const queryWords = queryLower.split(/[\s,.\-_/]+/).filter(w => w.length > 2);
    const scored: Array<{ skill: SkillDefinition; score: number }> = [];

    const skillsArray = this.getAvailableSkills();
    for (const skill of skillsArray) {
      let score = 0;
      for (const trigger of skill.triggers) {
        const triggerLower = trigger.toLowerCase();
        if (queryLower.includes(triggerLower)) {
          score += 10;
        } else {
          const triggerWords = triggerLower.split(/[\s\-_]+/);
          for (const tw of triggerWords) {
            if (tw.length > 2 && queryWords.includes(tw)) { score += 5; }
          }
        }
      }
      const nameTokens = skill.name.toLowerCase().split(/[\s\-_]+/);
      for (const token of nameTokens) {
        if (token.length > 2 && queryWords.includes(token)) { score += 8; }
      }
      for (const cap of skill.capabilities) {
        const capWords = cap.toLowerCase().split(/[\s,.\-_/()]+/).filter(w => w.length > 2);
        for (const cw of capWords) {
          if (queryWords.includes(cw)) { score += 2; break; }
        }
      }
      const descWords = skill.description.toLowerCase().split(/[\s,.\-_/()]+/).filter(w => w.length > 3);
      let descHits = 0;
      for (const dw of descWords) {
        if (queryWords.includes(dw) && descHits < 5) { score += 1; descHits++; }
      }
      if (score > 0) { scored.push({ skill, score }); }
    }
    scored.sort((a, b) => b.score - a.score);

    // Apply same score floor as findMatchingSkills
    if (scored.length > 0) {
      const topScore = scored[0].score;
      const floor = Math.max(3, Math.floor(topScore * 0.25));
      return scored.filter(s => s.score >= floor);
    }
    return scored;
  }

  /**
   * Get category from either legacy or dynamic skill
   */
  private getSkillCategory(skill: SkillDefinition): string {
    return getSkillCategoryHelper(skill);
  }

  /**
   * Apply a skill to a specific task (unified handling)
   */
  async applySkill(skillName: string, input: string, args?: string): Promise<string> {
    // Ensure dynamic loading is initialized
    await this.initialize();

    const skill = this.skills.get(skillName);
    if (!skill) {
      throw new Error(`Skill not found: ${skillName}`);
    }

    // Record usage in registry if this is a dynamic skill
    const startTime = Date.now();
    try {
      const response = this.generateSkillResponse(skill, input, args);
      const executionTime = Date.now() - startTime;

      // Record usage for both legacy and dynamic skills
      if (!('legacy' in skill && skill.legacy)) {
        await this.registry.recordUsage(skillName, executionTime, true);
      }

      return response;
    } catch (error) {
      const executionTime = Date.now() - startTime;

      // Record failed usage
      if (!('legacy' in skill && skill.legacy)) {
        await this.registry.recordUsage(skillName, executionTime, false);
      }

      throw error;
    }
  }

  /**
   * Get skill statistics and registry information
   */
  async getSkillStats(): Promise<any> {
    await this.initialize();

    const legacyCount = Array.from(this.skills.values()).filter(skill =>
      'legacy' in skill && skill.legacy
    ).length;

    const dynamicCount = this.skills.size - legacyCount;
    const registryStats = await this.registry.getSkillStats();

    return {
      total_skills: this.skills.size,
      legacy_skills: legacyCount,
      dynamic_skills: dynamicCount,
      registry_stats: registryStats,
      trust_distribution: this.getTrustDistribution(),
      pending_approvals: (await this.trustManager.getPendingApprovals()).length
    };
  }

  /**
   * Get trust level distribution
   */
  private getTrustDistribution(): Record<string, number> {
    const distribution: Record<string, number> = {
      [TrustLevel.BUILT_IN]: 0,
      [TrustLevel.VERIFIED]: 0,
      [TrustLevel.UNTRUSTED]: 0,
      legacy: 0
    };

    for (const skill of this.skills.values()) {
      if ('legacy' in skill && skill.legacy) {
        distribution.legacy++;
      } else if ('trust_level' in skill) {
        distribution[skill.trust_level]++;
      }
    }

    return distribution;
  }

  /**
   * Rescan and reload dynamic skills
   */
  async rescanSkills(): Promise<SkillScanResult> {
    const scanResult = await this.loader.scanAllSkills();
    await this.loadDynamicSkills();

    console.error(`Skills rescanned: ${scanResult.found_skills} found, ${scanResult.loaded_skills} loaded`);
    return scanResult;
  }

  /**
   * Get pending skill approvals
   */
  async getPendingApprovals(): Promise<any[]> {
    await this.initialize();
    return this.trustManager.getPendingApprovals();
  }

  /**
   * Generate a comprehensive skill response
   */
  private generateSkillResponse(skill: SkillDefinition, input: string, args?: string): string {
    const categoryEmoji: Record<string, string> = {
      development: '⭐',
      utility: '🏆',
      standard: '💡',
      security: '🔒',
      experimental: '🧪'
    };

    let response = `${categoryEmoji[this.getSkillCategory(skill)] || '💡'} **${skill.name.toUpperCase()} SKILL ACTIVATED**\n\n`;

    response += `**Task:** ${input}\n`;
    if (args) {
      response += `**Args:** ${args}\n`;
    }
    response += `\n`;

    // Generate skill-specific recommendations
    const guidanceMap: Record<string, () => string> = {
      'ultra-frontend': () => this.generateFrontendGuidance(input),
      'ultra-backend': () => this.generateBackendGuidance(input),
      'ultra-fullstack': () => this.generateFullstackGuidance(input),
      'ultra-css': () => this.generateCssGuidance(input),
      'master-debugger': () => this.generateDebuggingGuidance(input),
      'ultra-architect': () => this.generateArchitectureGuidance(input),
      'clean-code': () => this.generateCleanCodeGuidance(input),
      'self-learning': () => this.generateSelfLearningGuidance(input),
      'ai-agent-builder': () => this.generateAgentBuilderGuidance(input),
      'knowledge-base-builder': () => this.generateKnowledgeBaseGuidance(input),
      'llm-trainer': () => this.generateLlmTrainerGuidance(input),
      'test-automation': () => this.generateTestAutomationGuidance(input),
      'devops-cicd': () => this.generateDevopsGuidance(input),
      'data-engineering': () => this.generateDataEngineeringGuidance(input),
      'web-scraping': () => this.generateWebScrapingGuidance(input),
      'api-development': () => this.generateApiDevelopmentGuidance(input),
      'database-management': () => this.generateDatabaseGuidance(input),
      'security-testing': () => this.generateSecurityTestingGuidance(input),
      'mlops': () => this.generateMlopsGuidance(input),
      'cloud-infrastructure': () => this.generateCloudInfraGuidance(input),
      'monitoring-observability': () => this.generateMonitoringGuidance(input),
      'mcp-testing': () => this.generateMcpTestingGuidance(input),
      'windows-deployment': () => this.generateWindowsDeploymentGuidance(input),
    };

    const generator = guidanceMap[skill.name];
    if (generator) {
      response += generator();
    } else {
      response += this.generateGeneralGuidance(skill, input);
    }

    if (skill.pairsWith.length > 0 &&
        !skill.pairsWith.includes('all skills') &&
        !skill.pairsWith.some(p => p.includes('all skills'))) {
      response += `\n\n**Pairs with:** ${skill.pairsWith.join(', ')}`;
    }

    return response;
  }

  private generateFrontendGuidance(input: string): string {
    return `1. **Component Architecture**: Break down the UI into reusable components
2. **State Management**: Choose appropriate state solution (local, Zustand, or TanStack Query)
3. **Performance**: Implement code splitting, lazy loading, and optimize Core Web Vitals
4. **Accessibility**: Ensure WCAG 2.2 AA compliance with semantic HTML and ARIA
5. **Testing**: Set up component tests with Vitest and e2e tests with Playwright
6. **Modern Patterns**: Use React Server Components, streaming, and progressive enhancement`;
  }

  private generateBackendGuidance(input: string): string {
    let guidance = '';

    // Detect domain-specific context and inject relevant patterns
    const isEcommerce = /e-?commerce|shop|cart|checkout|order|inventory|payment|product catalog/i.test(input);
    const isMicroservices = /microservice|micro-service|distributed|service mesh|event.driven/i.test(input);
    const isAuth = /auth|login|oauth|jwt|session|identity|sso/i.test(input);
    const isRealtime = /real.?time|websocket|sse|streaming|push|notification/i.test(input);

    if (isEcommerce && isMicroservices) {
      guidance += `**E-Commerce Microservices Architecture:**
1. **Service Boundaries**: Order Service, Inventory Service, Payment Gateway, Product Catalog, User/Auth — each owns its database
2. **Saga Pattern**: Orchestrate order flow (reserve inventory → charge payment → confirm order → ship) with compensation on failure
3. **CQRS**: Separate write models (order placement) from read models (order history, product search) for different scaling needs
4. **Event Bus**: Kafka/RabbitMQ for inter-service communication — OrderCreated, PaymentProcessed, InventoryReserved events
5. **Idempotency**: Payment and order endpoints MUST be idempotent (use idempotency keys) to handle retries safely
6. **API Gateway**: Kong/AWS API Gateway for routing, rate limiting, and auth token validation at the edge
7. **Data Consistency**: Eventual consistency between services; use outbox pattern to guarantee event publishing`;
    } else if (isMicroservices) {
      guidance += `**Microservices Architecture:**
1. **Service Decomposition**: Identify bounded contexts — each service owns its data and business logic
2. **Communication**: Sync (REST/gRPC) for queries, async (events) for commands and state changes
3. **Saga Pattern**: Orchestrate distributed transactions with compensating actions on failure
4. **Service Discovery**: Use Consul/Eureka or Kubernetes DNS for service-to-service resolution
5. **Circuit Breakers**: Resilience4j/Polly to prevent cascade failures between services
6. **Observability**: Distributed tracing (Jaeger/Zipkin), correlated logs, per-service dashboards
7. **Data Strategy**: Database-per-service, outbox pattern for event publishing, eventual consistency`;
    } else if (isEcommerce) {
      guidance += `**E-Commerce Backend:**
1. **Product Catalog**: Full-text search (Elasticsearch/Meilisearch), faceted filtering, inventory tracking
2. **Cart & Checkout**: Session-based or persistent carts, price calculation with tax/discount rules
3. **Payment Integration**: Stripe/PayPal SDK, webhook verification, idempotent charge endpoints
4. **Order Pipeline**: State machine (pending → paid → fulfilled → shipped → delivered), event-driven notifications
5. **Inventory Management**: Stock reservation on checkout, automatic release on timeout/cancellation
6. **Security**: PCI DSS compliance for payment data, rate limiting on checkout endpoints`;
    } else if (isAuth) {
      guidance += `**Authentication & Authorization:**
1. **Token Strategy**: Short-lived access tokens (15min) + long-lived refresh tokens (7d) with rotation
2. **OAuth2/OIDC**: Authorization code flow with PKCE for SPAs, client credentials for service-to-service
3. **Password Hashing**: Argon2id (preferred) or bcrypt with cost factor 12+
4. **Session Management**: HttpOnly secure cookies, SameSite=Strict, CSRF tokens
5. **RBAC/ABAC**: Role-based for coarse access, attribute-based for fine-grained resource permissions
6. **MFA**: TOTP (authenticator apps) as baseline, WebAuthn/passkeys for phishing resistance`;
    } else if (isRealtime) {
      guidance += `**Real-Time Backend:**
1. **Protocol Choice**: WebSockets for bidirectional, SSE for server-push, long-polling as fallback
2. **Connection Management**: Heartbeats, reconnection logic, connection pooling with Redis pub/sub
3. **Scaling**: Sticky sessions or Redis adapter for multi-instance WebSocket broadcasting
4. **Backpressure**: Rate limit message frequency per client, queue overflow protection
5. **State Sync**: Conflict resolution strategy (last-write-wins, CRDTs, or operational transforms)
6. **Fallback**: Graceful degradation to polling when WebSocket connections fail`;
    } else {
      // General backend guidance
      guidance += `1. **Architecture Design**: Choose between monolith, microservices, or modular monolith based on team size and deployment needs
2. **API Design**: RESTful with OpenAPI spec or GraphQL with schema-first approach, proper versioning (URL path or header)
3. **Database Strategy**: Design normalized schema, add indexes for query patterns, implement connection pooling and caching layer
4. **Authentication**: JWT with refresh token rotation, or session-based with HttpOnly cookies — depends on client type
5. **Scalability**: Rate limiting (token bucket), horizontal scaling behind load balancer, cache-aside pattern with Redis
6. **Monitoring**: Structured JSON logging, Prometheus metrics, health/readiness endpoints, distributed tracing`;
    }

    return guidance;
  }

  private generateDebuggingGuidance(input: string): string {
    return `**6-Phase Root Cause Analysis:**

**Phase 1 - Reproduce**: Create minimal reproduction case
**Phase 2 - Isolate**: Narrow down to specific component/function
**Phase 3 - Analyze**: Use debugger, logs, and profiling tools
**Phase 4 - Hypothesize**: Form testable theories about root cause
**Phase 5 - Test**: Validate theories with systematic testing
**Phase 6 - Fix**: Implement fix and verify resolution

**Advanced Techniques:**
• Git bisect for regression hunting
• Time-travel debugging with rr/gdb
• Memory profiling with valgrind/heaptrack
• Distributed tracing for microservices
• Chaos engineering for resilience testing`;
  }

  private generateArchitectureGuidance(input: string): string {
    return `1. **Requirements Analysis**: Gather functional and non-functional requirements
2. **System Design**: Choose architectural patterns and technology stack
3. **Scalability Planning**: Design for current needs with future growth path
4. **Security Architecture**: Implement defense in depth and zero trust principles
5. **Data Architecture**: Design data flow, storage, and processing strategies
6. **Operational Excellence**: Plan deployment, monitoring, and incident response
7. **Documentation**: Create ADRs, system diagrams, and runbooks`;
  }

  private generateFullstackGuidance(input: string): string {
    return `1. **Monorepo Setup**: Configure Turborepo/Nx with shared packages (ui, db, config)
2. **End-to-End Type Safety**: Wire tRPC or GraphQL codegen between frontend and backend
3. **Database Package**: Shared Prisma schema, migrations, and seed data
4. **API Layer**: Type-safe client generation, error handling, auth middleware
5. **Shared UI Library**: Component library with Storybook, exported from packages/ui
6. **CI/CD Pipeline**: Parallel builds per package, deploy only affected services
7. **Environment Validation**: Zod schemas for env vars, validated at build time`;
  }

  private generateCssGuidance(input: string): string {
    return `1. **Design Tokens**: Define color, spacing, and typography tokens (CSS custom properties)
2. **Cascade Layers**: Structure with @layer reset, base, components, utilities
3. **Container Queries**: Use @container for component-level responsive design
4. **Modern Selectors**: Leverage :has(), :is(), :where() for cleaner selectors
5. **Color System**: Use oklch() for perceptually uniform color palettes
6. **Animations**: Scroll-driven animations, View Transitions API for page nav
7. **Dark Mode**: Implement with color-scheme and light-dark() function`;
  }

  private generateCleanCodeGuidance(input: string): string {
    return `**Code Quality Checklist:**

1. **SOLID Violations**: Check single-responsibility, open-closed, dependency inversion
2. **Code Smells**: Hunt for long methods (>20 lines), large classes, feature envy, data clumps
3. **Refactoring**: Extract method, introduce parameter object, replace conditional with polymorphism
4. **Design Patterns**: Identify where Strategy, Observer, Factory, or Decorator apply
5. **Error Handling**: Replace generic catches with typed errors, use Result/Either patterns
6. **Naming**: Variables reveal intent, functions describe action, classes describe responsibility
7. **Tests**: Each refactored unit has a test; refactor under green tests only

**Quick Wins:**
• Guard clauses instead of nested if/else
• Early returns to reduce indentation
• Const by default, let only when mutation needed
• Eliminate magic numbers with named constants`;
  }

  private generateSelfLearningGuidance(input: string): string {
    return `**6-Phase Learning Loop:**

1. **Detect**: Classify the knowledge gap (unknown-unknown, known-unknown, outdated)
2. **Research**: Multi-source search with credibility scoring (official docs > blog posts > forums)
3. **Synthesize**: Cross-validate findings, identify consensus and contradictions
4. **Apply**: Test the learned solution against the original problem
5. **Persist**: Store validated knowledge in the knowledge base with confidence level
6. **Improve**: Monitor outcomes, promote/demote knowledge based on real-world results

**Knowledge Base Commands:**
• Search: \`python manager.py --search "query"\`
• Stats: \`python manager.py --stats\`
• Add: Document findings with HIGH/MEDIUM/LOW confidence tags`;
  }

  private generateAgentBuilderGuidance(input: string): string {
    return `1. **Agent Architecture**: Choose pattern — ReAct (reason+act), Plan-and-Execute, or multi-agent
2. **Tool Design**: Define clear tool schemas with input validation and error handling
3. **Memory Strategy**: Short-term (conversation buffer), long-term (vector store), working memory
4. **Orchestration**: Single agent vs. CrewAI/AutoGen multi-agent with role assignment
5. **Guardrails**: Input validation, output parsing, max iterations, cost limits
6. **Evaluation**: Test with diverse inputs, measure task completion rate and cost per task

**Framework Selection:**
• LangChain/LangGraph — most flexibility, largest ecosystem
• CrewAI — best for role-based multi-agent teams
• AutoGen — best for conversational agent patterns`;
  }

  private generateKnowledgeBaseGuidance(input: string): string {
    return `1. **Document Ingestion**: Parse PDFs/HTML/markdown, clean and normalize text
2. **Chunking Strategy**: Choose chunk size (512-1024 tokens), overlap (10-20%), respect boundaries
3. **Embedding Model**: Select model (OpenAI, Cohere, local sentence-transformers)
4. **Vector Store**: Configure pgvector, Chroma, or Qdrant with proper indexing (HNSW/IVF)
5. **Retrieval Pipeline**: Hybrid search (dense + BM25 sparse), re-ranking with cross-encoder
6. **RAG Chain**: Context assembly, prompt template, citation tracking, hallucination detection

**Key Metrics:**
• Retrieval: Recall@K, MRR, NDCG
• Generation: Faithfulness, relevance, answer correctness`;
  }

  private generateLlmTrainerGuidance(input: string): string {
    return `1. **Dataset Preparation**: Format as instruction/response pairs, clean and deduplicate
2. **Base Model Selection**: Choose size vs. capability tradeoff for your VRAM (32GB RTX 5090)
3. **Training Method**: LoRA (r=16-64, alpha=32-128) or QLoRA (4-bit quantized base)
4. **Hyperparameters**: lr=2e-4, epochs=3-5, batch_size=4 with gradient accumulation
5. **Training**: Launch with Unsloth for 2x speed, monitor loss curves in real-time
6. **Evaluation**: Run benchmark suite, compare base vs. fine-tuned on domain tasks
7. **Export**: Merge LoRA adapters, convert to GGUF for Ollama deployment

**RTX 5090 Sweet Spots:**
• 7B models: Full fine-tune possible, LoRA trivial
• 13-32B models: QLoRA fits comfortably
• 70B models: QLoRA with 4-bit, gradient checkpointing`;
  }

  private generateTestAutomationGuidance(input: string): string {
    return `1. **Test Strategy**: Define pyramid — unit (70%), integration (20%), E2E (10%)
2. **Framework Selection**: Vitest/Jest (unit), Playwright (E2E), pytest (API)
3. **Page Object Model**: Create maintainable page objects for UI automation
4. **Data Management**: Test fixtures, factories, database seeding, cleanup
5. **CI Integration**: Run tests in pipeline, fail fast, parallel execution
6. **Reporting**: HTML reports, screenshot on failure, video recording for E2E

**Platform-Specific:**
• Web: Playwright (cross-browser, auto-wait, trace viewer)
• Mobile: Appium or Detox (React Native)
• API: pytest + httpx, or REST Assured
• RPA: Power Automate, UiPath for desktop automation
• UFT One: VBScript-based, for enterprise SAP/Oracle testing`;
  }

  private generateDevopsGuidance(input: string): string {
    return `1. **Pipeline Design**: Trigger → Build → Test → Scan → Deploy → Verify
2. **Containerization**: Multi-stage Dockerfile, .dockerignore, minimal base images
3. **Orchestration**: Docker Compose (dev), Kubernetes (prod) with Helm charts
4. **IaC**: Terraform for cloud resources, version-controlled, plan before apply
5. **GitOps**: ArgoCD or Flux for declarative deployments from Git
6. **Secrets**: Never in code — use vault, sealed-secrets, or cloud secret managers

**GitHub Actions Quick Start:**
• Build matrix for multi-platform
• Caching (node_modules, Docker layers)
• Environment protection rules for prod
• OIDC for cloud auth (no stored credentials)`;
  }

  private generateDataEngineeringGuidance(input: string): string {
    return `1. **Pipeline Architecture**: Choose batch (Airflow), stream (Kafka), or hybrid
2. **Medallion Layers**: Bronze (raw) → Silver (cleaned) → Gold (business-ready)
3. **Transformations**: dbt for SQL-based, Polars for DataFrame-based processing
4. **Data Quality**: Great Expectations or Soda for schema/value/freshness checks
5. **Orchestration**: Airflow DAGs with retry, alerting, SLA monitoring
6. **Storage**: Parquet on S3/GCS for lakes, PostgreSQL/ClickHouse for warehouses

**Performance Tips:**
• Polars over Pandas for 10-100x speedup on large datasets
• Partitioning by date for time-series data
• Incremental processing over full reloads when possible`;
  }

  private generateWebScrapingGuidance(input: string): string {
    return `1. **Target Analysis**: Inspect page structure, identify data patterns, check robots.txt
2. **Tool Selection**: requests+BS4 (static), Playwright (JS-rendered), Scrapy (at scale)
3. **Selectors**: CSS selectors for simple, XPath for complex, regex as last resort
4. **Anti-Detection**: Rotate user agents, use proxies, respect rate limits, randomize delays
5. **Data Extraction**: Parse structured data, handle pagination, normalize output
6. **Storage**: JSON lines for streaming, CSV for tabular, database for dedup

**Ethics Checklist:**
• Respect robots.txt and terms of service
• Rate limit requests (1-2 req/sec minimum delay)
• Cache responses to avoid re-fetching
• Identify your bot in User-Agent string`;
  }

  private generateApiDevelopmentGuidance(input: string): string {
    return `1. **API Design**: Resource-oriented URLs, proper HTTP methods, consistent naming
2. **Schema Definition**: Pydantic/Zod models for request/response validation
3. **Authentication**: JWT access tokens (short-lived) + refresh tokens, or API keys
4. **Error Handling**: RFC 7807 Problem Details format, consistent error codes
5. **Rate Limiting**: Token bucket per user/endpoint, return X-RateLimit headers
6. **Documentation**: OpenAPI 3.1 spec, auto-generated from code annotations

**FastAPI Quick Pattern:**
\`\`\`
app = FastAPI()
@app.get("/items/{id}", response_model=ItemResponse)
async def get_item(id: int, db: Session = Depends(get_db)):
    ...
\`\`\``;
  }

  private generateDatabaseGuidance(input: string): string {
    return `1. **Schema Design**: Normalize to 3NF, denormalize strategically for read paths
2. **Indexing**: B-tree for equality/range, GIN for JSONB/full-text, GiST for spatial
3. **Query Optimization**: EXPLAIN ANALYZE, avoid N+1, use CTEs for readability
4. **Migrations**: Forward-only, expand-contract for zero-downtime changes
5. **Connection Pooling**: PgBouncer or built-in pool, size = (cores * 2) + disks
6. **Caching**: Redis for hot data, materialized views for complex aggregations

**PostgreSQL Specifics:**
• pgvector for embedding similarity search
• JSONB for flexible schema within relational model
• Partitioning for tables > 100M rows
• pg_stat_statements for query performance monitoring`;
  }

  private generateSecurityTestingGuidance(input: string): string {
    return `**OWASP Top 10 Testing Checklist:**

1. **A01 Broken Access Control**: Test every endpoint with different roles, verify deny-by-default
2. **A02 Crypto Failures**: Scan for weak algorithms, exposed secrets, missing TLS
3. **A03 Injection**: Test all inputs with SQL, XSS, command injection payloads
4. **A04 Insecure Design**: Review threat model, check for missing business logic validation
5. **A05 Misconfiguration**: Scan for default credentials, verbose errors, unnecessary features

**Tool Workflow:**
• SAST: Semgrep/CodeQL on every PR
• DAST: OWASP ZAP against staging
• SCA: Trivy/Snyk for dependency vulnerabilities
• Secrets: TruffleHog/GitLeaks on git history
• Container: Trivy scan on Docker images before deploy`;
  }

  private generateMlopsGuidance(input: string): string {
    return `1. **Experiment Tracking**: MLflow for parameters, metrics, artifacts, model registry
2. **Feature Store**: Feast for online/offline feature serving with point-in-time correctness
3. **Model Serving**: BentoML for REST API, TorchServe for PyTorch, TensorRT for GPU inference
4. **Monitoring**: Evidently for data drift, prediction drift, and model quality metrics
5. **Pipeline Orchestration**: Kubeflow or Airflow for training → evaluation → deployment
6. **A/B Testing**: Shadow mode first, then gradual rollout with statistical significance checks

**Model Lifecycle:**
Train → Validate → Register → Stage → Deploy → Monitor → Retrain`;
  }

  private generateCloudInfraGuidance(input: string): string {
    return `1. **Architecture**: Design VPC/network topology, subnets, security groups
2. **Compute**: Right-size instances, use spot/preemptible for fault-tolerant workloads
3. **Storage**: S3/GCS lifecycle policies, tiering (hot/warm/cold/archive)
4. **IaC**: Terraform modules, remote state, workspace per environment
5. **Serverless**: Lambda/Cloud Functions for event-driven, API Gateway for HTTP
6. **Cost**: Tag everything, set billing alerts, reserved instances for baseline load

**AWS Quick Reference:**
• VPC + ALB + ECS Fargate for containerized apps
• RDS Multi-AZ for database HA
• CloudFront + S3 for static assets
• EventBridge + Lambda for event processing`;
  }

  private generateMonitoringGuidance(input: string): string {
    return `1. **Metrics**: Prometheus for collection, define RED metrics (Rate, Errors, Duration)
2. **Logging**: Structured JSON logs, correlation IDs, ship to Loki/ELK
3. **Tracing**: OpenTelemetry SDK, Jaeger/Tempo for distributed trace visualization
4. **Dashboards**: Grafana with 4 golden signals per service (latency, traffic, errors, saturation)
5. **Alerting**: Route by severity, PagerDuty for P1, Slack for P2+, runbook links in alerts
6. **SLOs**: Define SLIs (latency p99, error rate), set SLOs (99.9%), track error budgets

**Incident Response:**
Detect → Triage → Mitigate → Root Cause → Remediate → Postmortem`;
  }

  private generateMcpTestingGuidance(input: string): string {
    return `**MCP Server Testing Protocol (from real deployment lessons):**

1. **Protocol Compliance**: Verify ONLY JSON-RPC messages on stdout — no console.log, no emojis, no status text
2. **stdio Stream Audit**: Grep source for console.log/console.warn — ALL must be console.error in MCP servers
3. **Config Validation**: Check claude_desktop_config.json has correct server entry, args paths, env vars
4. **Path Validation**: Test with Windows drive letters (C:\\), forward slashes (C:/), backslashes, UNC paths
5. **Spawn Testing**: Verify shell:true for Windows .cmd wrappers (npm, npx) and builtins (dir, echo)
6. **Security Regex Audit**: Ensure path validation regex allows colons (drive letters) and backslashes on Windows
7. **End-to-End**: Pipe JSON-RPC initialize + tool call via stdin, verify clean JSON response on stdout
8. **Claude Desktop Integration**: Restart Desktop, verify tool count, run each tool manually

**Critical Rule:** If it writes to stdout, it MUST be valid JSON-RPC. Everything else goes to stderr.

**Common Windows Failures:**
• ENOENT: Missing shell:true in spawn() for .cmd files
• Regex blocking C: drive letter paths
• Working directory mismatch (Claude Desktop app dir vs project dir)`;
  }

  private generateWindowsDeploymentGuidance(input: string): string {
    return `**Windows-Specific Deployment Checklist:**

1. **Path Handling**: Use path.join() or path.resolve() — never hardcode separators
2. **Drive Letters**: Security regex must allow ':' in paths (C:\\Users\\...)
3. **Backslashes**: Regex patterns must allow '\\' for Windows paths — don't include in injection patterns
4. **Process Spawning**: Always use shell:true on Windows for .cmd/.bat wrappers and builtins
5. **Environment Variables**: Use %APPDATA%, %LOCALAPPDATA%, %USERPROFILE% (or process.env equivalents)
6. **Long Paths**: Enable LongPathsEnabled in registry or use \\\\?\\ prefix for paths > 260 chars
7. **Line Endings**: Git config core.autocrlf, .gitattributes for consistent line endings

**Cross-Platform Patterns:**
\`\`\`typescript
import { platform } from 'os';
const isWindows = platform() === 'win32';
spawn(cmd, args, { shell: isWindows }); // shell:true only on Windows
\`\`\`

**Debugging Windows Failures:**
• ENOENT: Usually missing shell:true or wrong PATH
• EPERM: Run as administrator or check file locks
• Path blocked: Review security regex for Windows-incompatible patterns`;
  }

  private generateGeneralGuidance(skill: SkillDefinition, input: string): string {
    return `1. **Analysis**: Break down the task into manageable components
2. **Planning**: Create a step-by-step implementation strategy
3. **Best Practices**: Apply industry standards and proven patterns
4. **Implementation**: Use the skill's specialized knowledge and tools
5. **Testing**: Validate the solution meets requirements
6. **Documentation**: Document the approach and lessons learned

**Skill-Specific Considerations:**
${skill.capabilities.slice(0, 3).map(cap => `• ${cap}`).join('\n')}`;
  }
}

// ── Initialise ───────────────────────────────────────────────────────────────

/**
 * Creates a fully configured skills-bridge MCP server.
 * Transport-agnostic: caller connects their own transport (stdio, SSE, HTTP).
 */
export function createSkillsBridgeServer() {

const skills = new SkillsBridge({
  skillsPath: process.env.SKILLS_PATH,
  enabledSkills: process.env.ENABLED_SKILLS?.split(','),
  timeout: process.env.TIMEOUT ? parseInt(process.env.TIMEOUT, 10) : undefined,
});

// Phase 4: Initialize Cowork integration components
const protocolHandler = new ProtocolHandler();
const stateManager = StateManager.getInstance();
stateManager.startSession();

const orchestrator = new Orchestrator({
  allowedPaths: process.env.ALLOWED_PATHS?.split(',') || [
    process.env.USERPROFILE || process.env.HOME || '.',
  ],
  blockedCommands: (process.env.BLOCKED_COMMANDS?.split(',') || [
    'rm', 'rmdir', 'del', 'format', 'fdisk', 'mkfs',
    'dd', 'shutdown', 'reboot', 'halt', 'poweroff',
  ]),
  timeout: process.env.TIMEOUT ? parseInt(process.env.TIMEOUT, 10) : 30000,
  maxFileSize: 10 * 1024 * 1024,
  readOnly: process.env.READ_ONLY === 'true',
});

const server = new Server(
  { name: 'skills-bridge', version: '0.3.0' },
  { capabilities: { tools: {} } },
);

// ── Tool definitions ─────────────────────────────────────────────────────────

const tools: Tool[] = [
  {
    name: 'list_skills',
    description: 'List all available Claude Code skills with their capabilities',
    inputSchema: {
      type: 'object',
      properties: {
        category: {
          type: 'string',
          enum: ['development', 'utility', 'standard', 'security', 'experimental', 'all'],
          description: 'Filter skills by category (default: all)',
          default: 'all',
        },
      },
    },
  },
  {
    name: 'find_skills',
    description: 'Find skills that match specific keywords or triggers',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Keywords to search for (e.g., "react", "debugging", "database")',
        },
      },
      required: ['query'],
    },
  },
  {
    name: 'apply_skill',
    description: 'Apply a specific skill to your task (like invoking Claude Code skills)',
    inputSchema: {
      type: 'object',
      properties: {
        skillName: {
          type: 'string',
          description: 'Name of the skill to apply (e.g., "ultra-frontend", "master-debugger")',
        },
        input: {
          type: 'string',
          description: 'Description of the task you want help with',
        },
        args: {
          type: 'string',
          description: 'Additional arguments or context for the skill (optional)',
        },
      },
      required: ['skillName', 'input'],
    },
  },
  {
    name: 'auto_skill_match',
    description: 'Automatically find and apply the best skill for your task',
    inputSchema: {
      type: 'object',
      properties: {
        request: {
          type: 'string',
          description: 'Description of what you want to accomplish',
        },
      },
      required: ['request'],
    },
  },
  // Phase 3A: Dynamic Skill Management Tools
  {
    name: 'skill_stats',
    description: 'Get statistics about skills, registry, and usage analytics',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'rescan_skills',
    description: 'Rescan and reload dynamic skills from the skills directory',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'get_pending_approvals',
    description: 'Get list of skills pending approval for trust management',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  // Phase 4: Cowork Integration Tools
  {
    name: 'healthcheck',
    description: 'Diagnose bridge health: server version, base dir, log dir, writable dirs, protocol version, Cowork status',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'execute_skill',
    description: 'Execute a skill with actual file/shell operations (write code, run commands). Turns guidance into action.',
    inputSchema: {
      type: 'object',
      properties: {
        skillName: {
          type: 'string',
          description: 'Name of the skill to execute (e.g., "ultra-frontend")',
        },
        task: {
          type: 'string',
          description: 'What to build or do (e.g., "create a React dashboard component")',
        },
        steps: {
          type: 'array',
          description: 'Explicit steps to execute (optional - auto-generated if omitted)',
          items: {
            type: 'object',
            properties: {
              name: { type: 'string', description: 'Step name' },
              type: { type: 'string', enum: ['read', 'write', 'edit', 'shell', 'glob'], description: 'Operation type' },
              params: { type: 'object', description: 'Operation parameters' },
            },
            required: ['name', 'type', 'params'],
          },
        },
      },
      required: ['skillName', 'task'],
    },
  },
  {
    name: 'bridge_status',
    description: 'Get session state, skill usage stats, and bridge health across all bridges',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
];

// ── Handlers ─────────────────────────────────────────────────────────────────

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'list_skills': {
        // Validate input with enhanced security schema
        const validatedArgs = SkillsValidationSchemas.listSkills.parse(args);
        const { category } = validatedArgs;

        // Log tool execution start
        await SkillsSecurityLogger.logSecurityEvent({
          type: 'TOOL_EXECUTION',
          severity: 'LOW',
          operation: 'list_skills',
          reason: `Starting skill listing operation for category: ${category}`
        });

        const availableSkills = skills.getAvailableSkills();

        const filteredSkills = category === 'all'
          ? availableSkills
          : availableSkills.filter(skill => skill.category === category);

        const skillsList = filteredSkills.map((skill) => {
          const categoryEmoji: Record<string, string> = { development: '⭐', utility: '🏆', standard: '💡', security: '🔒', experimental: '🧪' };
          const category = getSkillCategoryHelper(skill);
          return `${categoryEmoji[category] || '💡'} **${skill.name}** (${category})\n   ${skill.description}\n   Triggers: ${skill.triggers.slice(0, 5).join(', ')}`;
        }).join('\n\n');

        const summary = `**Available Claude Code Skills (${filteredSkills.length} total)**\n\n${skillsList}\n\n**Usage:** Use \`apply_skill\` to activate a specific skill, or \`auto_skill_match\` to find the best skill automatically.`;

        // Log successful tool execution
        await SkillsSecurityLogger.logToolExecution(name, validatedArgs, 'SUCCESS', `Returned ${filteredSkills.length} skills`);

        return { content: [{ type: 'text', text: summary }] };
      }

      case 'find_skills': {
        // Validate and sanitize input with enhanced security schema
        const validatedArgs = SkillsValidationSchemas.findSkills.parse(args);
        const { query } = validatedArgs;

        // Log tool execution start with security context
        await SkillsSecurityLogger.logSecurityEvent({
          type: 'TOOL_EXECUTION',
          severity: 'LOW',
          operation: 'find_skills',
          reason: `Starting skill search for query: ${query.substring(0, 100)}`
        });

        const matchingSkills = skills.findMatchingSkills(query);

        if (matchingSkills.length === 0) {
          await SkillsSecurityLogger.logToolExecution(name, validatedArgs, 'SUCCESS', 'No skills found');
          return { content: [{ type: 'text', text: `No skills found matching "${query}". Use \`list_skills\` to see all available skills.` }] };
        }

        const skillsList = matchingSkills.map((skill) => {
          const categoryEmoji: Record<string, string> = { development: '⭐', utility: '🏆', standard: '💡', security: '🔒', experimental: '🧪' };
          const category = getSkillCategoryHelper(skill);
          return `${categoryEmoji[category] || '💡'} **${skill.name}** (${category})\n   ${skill.description}`;
        }).join('\n\n');

        const result = `**Skills matching "${query}" (${matchingSkills.length} found)**\n\n${skillsList}\n\n**Next:** Use \`apply_skill\` with one of these skill names to activate it.`;

        await SkillsSecurityLogger.logToolExecution(name, validatedArgs, 'SUCCESS', `Found ${matchingSkills.length} matching skills`);
        return { content: [{ type: 'text', text: result }] };
      }

      case 'apply_skill': {
        // Validate and sanitize input with enhanced security schema
        const validatedArgs = SkillsValidationSchemas.applySkill.parse(args);
        const { skillName, input, args: skillArgs } = validatedArgs;

        // Enhanced skill name validation
        const skillValidation = SkillSecurityValidator.validateSkillName(skillName);
        if (!skillValidation.valid) {
          await SkillsSecurityLogger.logSecurityEvent({
            type: 'SKILL_BLOCKED',
            severity: 'HIGH',
            operation: 'apply_skill',
            skillName,
            reason: skillValidation.reason || 'Skill validation failed'
          });
          throw new Error(skillValidation.reason || 'Invalid skill');
        }

        // Enhanced input validation
        const inputValidation = await SkillSecurityValidator.validateSkillInput(skillName, input);
        if (!inputValidation.valid) {
          await SkillsSecurityLogger.logSecurityEvent({
            type: 'INPUT_VALIDATION',
            severity: 'HIGH',
            operation: 'apply_skill_input_validation',
            skillName,
            reason: inputValidation.reason || 'Input validation failed'
          });
          throw new Error(inputValidation.reason || 'Invalid input');
        }

        // Log skill application start
        await SkillsSecurityLogger.logSecurityEvent({
          type: 'SKILL_ACCESS',
          severity: 'LOW',
          operation: 'apply_skill',
          skillName,
          reason: `Applying skill ${skillName} with validated input`
        });

        const result = await skills.applySkill(skillName, input, skillArgs);
        await SkillsSecurityLogger.logToolExecution(name, validatedArgs, 'SUCCESS', `Applied skill: ${skillName}`);
        return { content: [{ type: 'text', text: result }] };
      }

      case 'auto_skill_match': {
        // Validate and sanitize input with enhanced security schema
        const validatedArgs = SkillsValidationSchemas.autoSkillMatch.parse(args);
        const { request } = validatedArgs;

        // Log auto-match attempt with security context
        await SkillsSecurityLogger.logSecurityEvent({
          type: 'TOOL_EXECUTION',
          severity: 'LOW',
          operation: 'auto_skill_match',
          reason: `Starting auto skill match for request: ${request.substring(0, 100)}`
        });

        const scoredMatches = skills.findMatchingSkillsWithScores(request);

        if (scoredMatches.length === 0) {
          await SkillsSecurityLogger.logToolExecution(name, validatedArgs, 'SUCCESS', 'No matching skills found');
          return { content: [{ type: 'text', text: `No skills automatically matched for "${request}". Try using \`find_skills\` with specific keywords, or \`list_skills\` to browse all available skills.` }] };
        }

        // Apply the best matching skill with enhanced validation
        const bestMatch = scoredMatches[0];

        // Validate skill selection
        const skillValidation = SkillSecurityValidator.validateSkillName(bestMatch.skill.name);
        if (!skillValidation.valid) {
          await SkillsSecurityLogger.logSecurityEvent({
            type: 'SKILL_BLOCKED',
            severity: 'HIGH',
            operation: 'auto_skill_match_validation',
            skillName: bestMatch.skill.name,
            reason: skillValidation.reason || 'Auto-matched skill validation failed'
          });
          throw new Error('Auto-matched skill failed validation');
        }

        // Log skill application
        await SkillsSecurityLogger.logSecurityEvent({
          type: 'SKILL_ACCESS',
          severity: 'LOW',
          operation: 'auto_skill_match_apply',
          skillName: bestMatch.skill.name,
          reason: `Auto-applying best matching skill: ${bestMatch.skill.name} (score: ${bestMatch.score})`
        });

        const result = await skills.applySkill(bestMatch.skill.name, request);

        let response = `**AUTO-MATCHED SKILL: ${bestMatch.skill.name.toUpperCase()}** (score: ${bestMatch.score})\n\n`;

        if (scoredMatches.length > 1) {
          const runners = scoredMatches.slice(1, 4).map(s => `${s.skill.name} (${s.score})`).join(', ');
          response += `*Also considered: ${runners}*\n\n`;
        }

        response += result;

        await SkillsSecurityLogger.logToolExecution(name, validatedArgs, 'SUCCESS', `Auto-matched and applied skill: ${bestMatch.skill.name} (score: ${bestMatch.score})`);
        return { content: [{ type: 'text', text: response }] };
      }

      // Phase 3A: Dynamic Skill Management Handlers
      case 'skill_stats': {
        await SkillsSecurityLogger.logSecurityEvent({
          type: 'TOOL_EXECUTION',
          severity: 'LOW',
          operation: 'skill_stats',
          reason: 'Getting skill statistics and registry information'
        });

        const stats = await skills.getSkillStats();
        const statsText = `**Skills Bridge Statistics**

**Total Skills**: ${stats.total_skills}
- Legacy Skills: ${stats.legacy_skills}
- Dynamic Skills: ${stats.dynamic_skills}

**Trust Distribution**:
- System (Built-in): ${stats.trust_distribution.system || 0}
- Verified: ${stats.trust_distribution.verified || 0}
- Untrusted: ${stats.trust_distribution.untrusted || 0}
- Legacy: ${stats.trust_distribution.legacy || 0}

**Pending Approvals**: ${stats.pending_approvals}

**Registry Stats**: ${JSON.stringify(stats.registry_stats, null, 2)}`;

        await SkillsSecurityLogger.logToolExecution(name, {}, 'SUCCESS', 'Statistics retrieved successfully');
        return { content: [{ type: 'text', text: statsText }] };
      }

      case 'rescan_skills': {
        await SkillsSecurityLogger.logSecurityEvent({
          type: 'TOOL_EXECUTION',
          severity: 'LOW',
          operation: 'rescan_skills',
          reason: 'Rescanning skills directory for new skills'
        });

        const scanResult = await skills.rescanSkills();
        const resultText = `**Skill Rescan Complete**

**Found**: ${scanResult.found_skills} skills
**Loaded**: ${scanResult.loaded_skills} skills
**Failed**: ${scanResult.failed_skills} skills
**Pending Approval**: ${scanResult.pending_approval} skills
**Scan Duration**: ${scanResult.scan_duration_ms}ms

${scanResult.errors.length > 0 ? `**Errors**:\n${scanResult.errors.map(e => `• ${e.skill_name}: ${e.error}`).join('\n')}` : '✅ No errors during scan'}

Use \`skill_stats\` to see updated statistics.`;

        await SkillsSecurityLogger.logToolExecution(name, {}, 'SUCCESS', `Rescanned: ${scanResult.found_skills} found, ${scanResult.loaded_skills} loaded`);
        return { content: [{ type: 'text', text: resultText }] };
      }

      case 'get_pending_approvals': {
        await SkillsSecurityLogger.logSecurityEvent({
          type: 'TOOL_EXECUTION',
          severity: 'LOW',
          operation: 'get_pending_approvals',
          reason: 'Getting pending skill approvals'
        });

        const pendingApprovals = await skills.getPendingApprovals();

        if (pendingApprovals.length === 0) {
          await SkillsSecurityLogger.logToolExecution(name, {}, 'SUCCESS', 'No pending approvals');
          return { content: [{ type: 'text', text: '✅ **No Skills Pending Approval**\n\nAll skills are either approved or automatically loaded.' }] };
        }

        const approvalsText = `**Skills Pending Approval (${pendingApprovals.length})**

${pendingApprovals.map((req, i) => `**${i + 1}. ${req.skill_name}**
- **Risk Level**: ${req.risk_assessment.risk_level}
- **Requested**: ${new Date(req.requested_at).toLocaleString()}
- **Expires**: ${req.expires_at ? new Date(req.expires_at).toLocaleString() : 'Never'}
- **Concerns**: ${req.risk_assessment.concerns.join(', ')}
- **Recommendations**: ${req.risk_assessment.recommendations.join(', ')}`).join('\n\n')}

**Note**: Skill approval must be handled manually for security. Review each skill carefully before approving.`;

        await SkillsSecurityLogger.logToolExecution(name, {}, 'SUCCESS', `Retrieved ${pendingApprovals.length} pending approvals`);
        return { content: [{ type: 'text', text: approvalsText }] };
      }

      // Phase 4: Cowork Integration Handlers
      case 'healthcheck': {
        await SkillsSecurityLogger.logSecurityEvent({
          type: 'TOOL_EXECUTION',
          severity: 'LOW',
          operation: 'healthcheck',
          reason: 'Running bridge health diagnostics'
        });

        const scriptDir = new URL('.', import.meta.url).pathname.replace(/^\/([A-Z]:)/i, '$1');
        const baseDir = join(scriptDir, '..', '..');
        const logDir = SkillsSecurityLogger['logDir'] || join(baseDir, 'logs');
        const dataDir = join(baseDir, 'data');

        const protocolInfo = protocolHandler.getProtocolVersion();
        const isCowork = protocolHandler.isCoworkEnabled();
        const clientInfo = protocolHandler.getClientInfo();

        const health = {
          server: {
            name: 'skills-bridge',
            version: '0.3.0',
            uptime: Math.floor(process.uptime()),
            pid: process.pid,
            nodeVersion: process.version,
          },
          paths: {
            baseDir,
            logDir,
            dataDir,
            cwd: process.cwd(),
            scriptDir,
            logDirWritable: existsSync(logDir),
            dataDirWritable: existsSync(dataDir),
          },
          protocol: {
            version: protocolInfo,
            isCowork,
            clientName: clientInfo.name,
            clientVersion: clientInfo.version,
            uiExtensionAvailable: protocolHandler.hasUIExtension(),
          },
          skills: {
            total: skills.getAvailableSkills().length,
            sessionId: stateManager.getSessionId(),
          },
          compatibility: protocolHandler.getCompatibilityNotes(),
        };

        const healthText = UIRenderer.isUIEnabled()
          ? UIRenderer.renderStats(
              Object.fromEntries([
                ['Server', `${health.server.name} v${health.server.version}`],
                ['Uptime', `${health.server.uptime}s`],
                ['Node', health.server.nodeVersion],
                ['Protocol', health.protocol.version],
                ['Cowork', health.protocol.isCowork ? 'Yes' : 'No'],
                ['UI Extension', health.protocol.uiExtensionAvailable ? 'Available' : 'Not available'],
                ['Client', `${health.protocol.clientName} v${health.protocol.clientVersion}`],
                ['Base Dir', health.paths.baseDir],
                ['CWD', health.paths.cwd],
                ['Log Dir', `${health.paths.logDir} (${health.paths.logDirWritable ? 'writable' : 'NOT writable'})`],
                ['Total Skills', health.skills.total],
                ['Session', health.skills.sessionId],
              ])
            ).text
          : JSON.stringify(health, null, 2);

        stateManager.recordBridgeHealth('skills-bridge', 'healthy', 'Healthcheck passed');

        await SkillsSecurityLogger.logToolExecution('healthcheck', {}, 'SUCCESS', 'Health diagnostics complete');
        return { content: [{ type: 'text', text: healthText }] };
      }

      case 'execute_skill': {
        const executeArgs = args as { skillName: string; task: string; steps?: Array<{ name: string; type: string; params: Record<string, any> }> };

        if (!executeArgs.skillName || !executeArgs.task) {
          throw new Error('skillName and task are required');
        }

        // Validate skill name
        const execSkillValidation = SkillSecurityValidator.validateSkillName(executeArgs.skillName);
        if (!execSkillValidation.valid) {
          throw new Error(execSkillValidation.reason || 'Invalid skill');
        }

        // Scan task input for injection
        const taskScan = SecurityScanner.scanInput(executeArgs.task);
        if (!taskScan.safe) {
          throw new Error(`Task input failed security scan: ${taskScan.issues.join(', ')}`);
        }

        await SkillsSecurityLogger.logSecurityEvent({
          type: 'SKILL_ACCESS',
          severity: 'LOW',
          operation: 'execute_skill',
          skillName: executeArgs.skillName,
          reason: `Executing skill with orchestration: ${executeArgs.task.substring(0, 100)}`
        });

        const startTime = Date.now();

        // Get skill guidance first
        const guidance = await skills.applySkill(executeArgs.skillName, executeArgs.task);

        // Execute steps if provided
        let orchestrationResult: string | undefined;
        if (executeArgs.steps && executeArgs.steps.length > 0) {
          const typedSteps = executeArgs.steps.map(s => ({
            name: s.name,
            type: s.type as 'read' | 'write' | 'edit' | 'shell' | 'glob',
            params: s.params,
          }));
          const result = await orchestrator.executeSteps(typedSteps);
          orchestrationResult = UIRenderer.isUIEnabled()
            ? UIRenderer.renderOrchestrationResult(
                result.steps.map(s => ({
                  name: s.name,
                  status: s.status === 'skipped' ? 'pending' : s.status,
                  output: s.output || s.error,
                }))
              ).text
            : result.summary;
        }

        const durationMs = Date.now() - startTime;
        stateManager.recordSkillUsage(executeArgs.skillName, executeArgs.task, true, durationMs);

        let response = `**EXECUTING: ${executeArgs.skillName.toUpperCase()}**\n\n`;
        response += guidance;
        if (orchestrationResult) {
          response += `\n\n---\n\n**Orchestration Results:**\n${orchestrationResult}`;
        }

        await SkillsSecurityLogger.logToolExecution('execute_skill', executeArgs, 'SUCCESS',
          `Executed ${executeArgs.skillName} in ${durationMs}ms`);
        return { content: [{ type: 'text', text: response }] };
      }

      case 'bridge_status': {
        await SkillsSecurityLogger.logSecurityEvent({
          type: 'TOOL_EXECUTION',
          severity: 'LOW',
          operation: 'bridge_status',
          reason: 'Getting bridge status and session state'
        });

        const usageStats = stateManager.getSkillUsageStats();
        const recentSkills = stateManager.getRecentSkills(5);
        const mostUsed = stateManager.getMostUsedSkills(5);
        const bridgeHealth = stateManager.getBridgeHealth();
        const sessionId = stateManager.getSessionId();

        const statusParts = [
          `**Bridge Status Report**\n`,
          `**Session**: ${sessionId}`,
          `**Protocol**: ${protocolHandler.getProtocolVersion()} (${protocolHandler.isCoworkEnabled() ? 'Cowork' : 'Classic'})`,
          `**UI Extension**: ${UIRenderer.isUIEnabled() ? 'Active' : 'Inactive'}`,
          `\n**Skill Usage Stats**:`,
          `- Total Invocations: ${usageStats.totalInvocations}`,
          `- Success Rate: ${(usageStats.successRate * 100).toFixed(1)}%`,
          `- Avg Duration: ${usageStats.avgDurationMs.toFixed(0)}ms`,
          `- Unique Skills Used: ${usageStats.uniqueSkillsUsed}`,
        ];

        if (mostUsed.length > 0) {
          statusParts.push(`\n**Most Used Skills**:`);
          for (const s of mostUsed) {
            statusParts.push(`- ${s.name}: ${s.count} uses (avg ${s.avgDurationMs.toFixed(0)}ms)`);
          }
        }

        if (recentSkills.length > 0) {
          statusParts.push(`\n**Recent Skills**:`);
          for (const s of recentSkills) {
            statusParts.push(`- ${s.skillName} (${s.success ? 'OK' : 'FAIL'}) - ${new Date(s.timestamp).toLocaleTimeString()}`);
          }
        }

        if (Object.keys(bridgeHealth).length > 0) {
          statusParts.push(`\n**Bridge Health**:`);
          for (const [name, health] of Object.entries(bridgeHealth)) {
            statusParts.push(`- ${name}: ${health.status} (last: ${new Date(health.lastCheck).toLocaleTimeString()})`);
          }
        }

        await SkillsSecurityLogger.logToolExecution('bridge_status', {}, 'SUCCESS', 'Status report generated');
        return { content: [{ type: 'text', text: statusParts.join('\n') }] };
      }

      default:
        // Log unknown tool attempts for security analysis
        await SkillsSecurityLogger.logSecurityEvent({
          type: 'INPUT_VALIDATION',
          severity: 'MEDIUM',
          operation: 'unknown_tool',
          reason: `Unknown tool requested: ${name}`
        });
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (err) {
    // Log all tool execution errors for security analysis
    if (err instanceof z.ZodError) {
      // Input validation errors
      await SkillsSecurityLogger.logSecurityEvent({
        type: 'INPUT_VALIDATION',
        severity: 'HIGH',
        operation: name,
        reason: `Input validation failed for ${name}: ${err.errors.map(e => e.message).join(', ')}`
      });

      await SkillsSecurityLogger.logToolExecution(name, args, 'ERROR', 'Input validation failed');
      return {
        content: [{ type: 'text', text: `Input validation error: ${err.errors.map(e => e.message).join(', ')}` }],
        isError: true,
      };
    } else {
      // Other execution errors
      await SkillsSecurityLogger.logSecurityEvent({
        type: 'TOOL_EXECUTION',
        severity: 'MEDIUM',
        operation: name,
        reason: `Tool execution failed for ${name}: ${errorMessage(err)}`
      });

      await SkillsSecurityLogger.logToolExecution(name, args, 'ERROR', errorMessage(err));
      return {
        content: [{ type: 'text', text: `Error: ${errorMessage(err)}` }],
        isError: true,
      };
    }
  }
});

return { server, skills, protocolHandler, stateManager, orchestrator };
} // end createSkillsBridgeServer

// ── Start (stdio) ────────────────────────────────────────────────────────────

async function main() {
  const { server, skills } = createSkillsBridgeServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);

  // Initialize dynamic skill loading
  try {
    await skills.initialize();
  } catch (error) {
    console.error('Skills initialization warning:', error);
  }

  console.error('Skills bridge MCP server running on stdio');
}

// Only start stdio when run directly (not when imported by sse-server)
const __currentFile = fileURLToPath(import.meta.url);
const __entryFile = process.argv[1] ? resolve(process.argv[1]) : '';
if (__currentFile === __entryFile) {
  main().catch((err) => {
    console.error('Server failed to start:', err);
    process.exit(1);
  });
}