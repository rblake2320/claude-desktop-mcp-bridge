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
import { join } from 'path';

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Extract a human-readable message from an unknown thrown value. */
function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
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
  /ignore\s+(previous|above|all)\s+(instructions?|prompts?|rules?)/i,
  /forget\s+(everything|all|previous|instructions?)/i,
  /act\s+as\s+(?:if\s+you\s+are\s+)?(?:a\s+)?(?:different|new|another)\s+(?:ai|assistant|bot|system)/i,
  /(?:^|\s)system\s*:\s*(?:you\s+are|act|behave|ignore)/i,
  /<\s*(?:system|admin|root|user)\s*>/i,
  /\[\s*(?:system|admin|root)\s*\]/i,
  /eval\s*\(|exec\s*\(|function\s*\(|=>\s*{/i, // Code injection
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
  private static logDir = join(process.cwd(), 'logs');
  private static securityLogPath = join(SkillsSecurityLogger.logDir, 'skills-bridge-security.log');

  static init() {
    if (!existsSync(SkillsSecurityLogger.logDir)) {
      mkdirSync(SkillsSecurityLogger.logDir, { recursive: true });
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
      input_hash: event.input ? require('crypto').createHash('sha256').update(event.input).digest('hex').substring(0, 16) : undefined,
      client: event.clientInfo || 'unknown'
    }) + '\n';

    try {
      await appendFile(SkillsSecurityLogger.securityLogPath, logEntry);
    } catch (error) {
      console.error('Failed to write skills security audit log:', error);
    }
  }

  static async logToolExecution(toolName: string, args: any, result: 'SUCCESS' | 'ERROR', details?: string) {
    const argsHash = require('crypto').createHash('sha256').update(JSON.stringify(args)).digest('hex').substring(0, 16);

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
    category: z.enum(['master', 'elite', 'standard', 'all']).default('all')
      .refine(
        (cat) => ['master', 'elite', 'standard', 'all'].includes(cat),
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

interface SkillDefinition {
  name: string;
  description: string;
  category: 'master' | 'elite' | 'standard';
  triggers: string[];
  capabilities: string[];
  pairsWith: string[];
}

const SKILL_DEFINITIONS: SkillDefinition[] = [
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
  }
];

// ── Skills Bridge ────────────────────────────────────────────────────────────

class SkillsBridge {
  private config: Config;
  private skills: Map<string, SkillDefinition>;

  constructor(config: Partial<Config> = {}) {
    this.config = ConfigSchema.parse(config);
    this.skills = new Map();

    // Initialize skills
    for (const skill of SKILL_DEFINITIONS) {
      if (!this.config.enabledSkills || this.config.enabledSkills.includes(skill.name)) {
        this.skills.set(skill.name, skill);
      }
    }
  }

  /**
   * Get all available skills
   */
  getAvailableSkills(): SkillDefinition[] {
    const skills: SkillDefinition[] = [];
    this.skills.forEach(skill => skills.push(skill));
    return skills;
  }

  /**
   * Find skills matching triggers/keywords
   */
  findMatchingSkills(query: string): SkillDefinition[] {
    const queryLower = query.toLowerCase();
    const matchingSkills: SkillDefinition[] = [];

    const skillsArray = this.getAvailableSkills();
    for (const skill of skillsArray) {
      // Check if query matches any triggers
      const matchesTriggers = skill.triggers.some(trigger =>
        queryLower.includes(trigger.toLowerCase()) ||
        trigger.toLowerCase().includes(queryLower)
      );

      // Check if query matches skill name or description
      const matchesContent =
        skill.name.toLowerCase().includes(queryLower) ||
        skill.description.toLowerCase().includes(queryLower) ||
        skill.capabilities.some(cap => cap.toLowerCase().includes(queryLower));

      if (matchesTriggers || matchesContent) {
        matchingSkills.push(skill);
      }
    }

    // Sort by category priority: master > elite > standard
    return matchingSkills.sort((a, b) => {
      const categoryOrder = { master: 0, elite: 1, standard: 2 };
      return categoryOrder[a.category] - categoryOrder[b.category];
    });
  }

  /**
   * Apply a skill to a specific task
   */
  async applySkill(skillName: string, input: string, args?: string): Promise<string> {
    const skill = this.skills.get(skillName);
    if (!skill) {
      throw new Error(`Skill not found: ${skillName}`);
    }

    // Generate skill response based on the skill definition
    return this.generateSkillResponse(skill, input, args);
  }

  /**
   * Generate a comprehensive skill response
   */
  private generateSkillResponse(skill: SkillDefinition, input: string, args?: string): string {
    const categoryEmoji = {
      master: '⭐',
      elite: '🏆',
      standard: '💡'
    };

    let response = `${categoryEmoji[skill.category]} **${skill.name.toUpperCase()} SKILL ACTIVATED**\n\n`;

    response += `**Task Analysis:** ${input}\n\n`;

    if (args) {
      response += `**Additional Arguments:** ${args}\n\n`;
    }

    response += `**Skill Overview:** ${skill.description}\n\n`;

    response += `**Key Capabilities Applied:**\n`;
    for (const capability of skill.capabilities.slice(0, 5)) {
      response += `• ${capability}\n`;
    }

    response += `\n**Recommended Approach for "${input}":**\n`;

    // Generate specific recommendations based on skill type
    if (skill.name.includes('frontend')) {
      response += this.generateFrontendGuidance(input);
    } else if (skill.name.includes('backend')) {
      response += this.generateBackendGuidance(input);
    } else if (skill.name.includes('debug')) {
      response += this.generateDebuggingGuidance(input);
    } else if (skill.name.includes('architect')) {
      response += this.generateArchitectureGuidance(input);
    } else {
      response += this.generateGeneralGuidance(skill, input);
    }

    if (skill.pairsWith.length > 0 && !skill.pairsWith.includes('all skills')) {
      response += `\n\n**Recommended Skill Combinations:**\n`;
      response += `This skill pairs well with: ${skill.pairsWith.join(', ')}\n`;
      response += `Consider using multiple skills together for comprehensive solutions.`;
    }

    response += `\n\n**Next Steps:**\n`;
    response += `1. Review the approach above\n`;
    response += `2. Ask follow-up questions for specific implementation details\n`;
    response += `3. Request code examples or detailed tutorials\n`;
    response += `4. Consider pairing with complementary skills if needed`;

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
    return `1. **Architecture Design**: Choose between monolith, microservices, or modular monolith
2. **API Design**: Implement RESTful or GraphQL APIs with proper versioning
3. **Database Strategy**: Design schema, optimize queries, and implement caching
4. **Authentication**: Set up JWT/OAuth2 with refresh tokens and proper security
5. **Scalability**: Implement rate limiting, load balancing, and horizontal scaling
6. **Monitoring**: Add logging, metrics, and health checks for observability`;
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

const skills = new SkillsBridge({
  skillsPath: process.env.SKILLS_PATH,
  enabledSkills: process.env.ENABLED_SKILLS?.split(','),
  timeout: process.env.TIMEOUT ? parseInt(process.env.TIMEOUT, 10) : undefined,
});

const server = new Server(
  { name: 'skills-bridge', version: '0.1.0' },
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
          enum: ['master', 'elite', 'standard', 'all'],
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

        const skillsList = filteredSkills.map(skill => {
          const categoryEmoji = { master: '⭐', elite: '🏆', standard: '💡' };
          return `${categoryEmoji[skill.category]} **${skill.name}** (${skill.category})\n   ${skill.description}\n   Triggers: ${skill.triggers.slice(0, 5).join(', ')}`;
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

        const skillsList = matchingSkills.map(skill => {
          const categoryEmoji = { master: '⭐', elite: '🏆', standard: '💡' };
          return `${categoryEmoji[skill.category]} **${skill.name}** (${skill.category})\n   ${skill.description}`;
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

        const matchingSkills = skills.findMatchingSkills(request);

        if (matchingSkills.length === 0) {
          await SkillsSecurityLogger.logToolExecution(name, validatedArgs, 'SUCCESS', 'No matching skills found');
          return { content: [{ type: 'text', text: `No skills automatically matched for "${request}". Try using \`find_skills\` with specific keywords, or \`list_skills\` to browse all available skills.` }] };
        }

        // Apply the best matching skill with enhanced validation
        const bestSkill = matchingSkills[0];

        // Validate skill selection
        const skillValidation = SkillSecurityValidator.validateSkillName(bestSkill.name);
        if (!skillValidation.valid) {
          await SkillsSecurityLogger.logSecurityEvent({
            type: 'SKILL_BLOCKED',
            severity: 'HIGH',
            operation: 'auto_skill_match_validation',
            skillName: bestSkill.name,
            reason: skillValidation.reason || 'Auto-matched skill validation failed'
          });
          throw new Error('Auto-matched skill failed validation');
        }

        // Log skill application
        await SkillsSecurityLogger.logSecurityEvent({
          type: 'SKILL_ACCESS',
          severity: 'LOW',
          operation: 'auto_skill_match_apply',
          skillName: bestSkill.name,
          reason: `Auto-applying best matching skill: ${bestSkill.name}`
        });

        const result = await skills.applySkill(bestSkill.name, request);

        let response = `**🎯 AUTO-MATCHED SKILL: ${bestSkill.name.toUpperCase()}**\n\n`;

        if (matchingSkills.length > 1) {
          response += `*Also considered: ${matchingSkills.slice(1, 4).map(s => s.name).join(', ')}*\n\n`;
        }

        response += result;

        await SkillsSecurityLogger.logToolExecution(name, validatedArgs, 'SUCCESS', `Auto-matched and applied skill: ${bestSkill.name}`);
        return { content: [{ type: 'text', text: response }] };
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

// ── Start ────────────────────────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Skills bridge MCP server running on stdio');
}

main().catch((err) => {
  console.error('Server failed to start:', err);
  process.exit(1);
});