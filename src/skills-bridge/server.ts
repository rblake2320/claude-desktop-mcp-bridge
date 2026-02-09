#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';

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
    return Array.from(this.skills.values());
  }

  /**
   * Find skills matching triggers/keywords
   */
  findMatchingSkills(query: string): SkillDefinition[] {
    const queryLower = query.toLowerCase();
    const matchingSkills: SkillDefinition[] = [];

    for (const skill of this.skills.values()) {
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
  async applySkill(skillName: string, task: string, context?: string): Promise<string> {
    const skill = this.skills.get(skillName);
    if (!skill) {
      throw new Error(`Skill not found: ${skillName}`);
    }

    // Generate skill response based on the skill definition
    return this.generateSkillResponse(skill, task, context);
  }

  /**
   * Generate a comprehensive skill response
   */
  private generateSkillResponse(skill: SkillDefinition, task: string, context?: string): string {
    const categoryEmoji = {
      master: '⭐',
      elite: '🏆',
      standard: '💡'
    };

    let response = `${categoryEmoji[skill.category]} **${skill.name.toUpperCase()} SKILL ACTIVATED**\n\n`;

    response += `**Task Analysis:** ${task}\n\n`;

    if (context) {
      response += `**Context Provided:** ${context}\n\n`;
    }

    response += `**Skill Overview:** ${skill.description}\n\n`;

    response += `**Key Capabilities Applied:**\n`;
    for (const capability of skill.capabilities.slice(0, 5)) {
      response += `• ${capability}\n`;
    }

    response += `\n**Recommended Approach for "${task}":**\n`;

    // Generate specific recommendations based on skill type
    if (skill.name.includes('frontend')) {
      response += this.generateFrontendGuidance(task);
    } else if (skill.name.includes('backend')) {
      response += this.generateBackendGuidance(task);
    } else if (skill.name.includes('debug')) {
      response += this.generateDebuggingGuidance(task);
    } else if (skill.name.includes('architect')) {
      response += this.generateArchitectureGuidance(task);
    } else {
      response += this.generateGeneralGuidance(skill, task);
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

  private generateFrontendGuidance(task: string): string {
    return `1. **Component Architecture**: Break down the UI into reusable components
2. **State Management**: Choose appropriate state solution (local, Zustand, or TanStack Query)
3. **Performance**: Implement code splitting, lazy loading, and optimize Core Web Vitals
4. **Accessibility**: Ensure WCAG 2.2 AA compliance with semantic HTML and ARIA
5. **Testing**: Set up component tests with Vitest and e2e tests with Playwright
6. **Modern Patterns**: Use React Server Components, streaming, and progressive enhancement`;
  }

  private generateBackendGuidance(task: string): string {
    return `1. **Architecture Design**: Choose between monolith, microservices, or modular monolith
2. **API Design**: Implement RESTful or GraphQL APIs with proper versioning
3. **Database Strategy**: Design schema, optimize queries, and implement caching
4. **Authentication**: Set up JWT/OAuth2 with refresh tokens and proper security
5. **Scalability**: Implement rate limiting, load balancing, and horizontal scaling
6. **Monitoring**: Add logging, metrics, and health checks for observability`;
  }

  private generateDebuggingGuidance(task: string): string {
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

  private generateArchitectureGuidance(task: string): string {
    return `1. **Requirements Analysis**: Gather functional and non-functional requirements
2. **System Design**: Choose architectural patterns and technology stack
3. **Scalability Planning**: Design for current needs with future growth path
4. **Security Architecture**: Implement defense in depth and zero trust principles
5. **Data Architecture**: Design data flow, storage, and processing strategies
6. **Operational Excellence**: Plan deployment, monitoring, and incident response
7. **Documentation**: Create ADRs, system diagrams, and runbooks`;
  }

  private generateGeneralGuidance(skill: SkillDefinition, task: string): string {
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
        task: {
          type: 'string',
          description: 'Description of the task you want help with',
        },
        context: {
          type: 'string',
          description: 'Additional context about your project or requirements (optional)',
        },
      },
      required: ['skillName', 'task'],
    },
  },
  {
    name: 'auto_skill_match',
    description: 'Automatically find and apply the best skill for your task',
    inputSchema: {
      type: 'object',
      properties: {
        task: {
          type: 'string',
          description: 'Description of what you want to accomplish',
        },
        context: {
          type: 'string',
          description: 'Additional context about your project or requirements (optional)',
        },
      },
      required: ['task'],
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
        const { category = 'all' } = args as { category?: string };
        const availableSkills = skills.getAvailableSkills();

        const filteredSkills = category === 'all'
          ? availableSkills
          : availableSkills.filter(skill => skill.category === category);

        const skillsList = filteredSkills.map(skill => {
          const categoryEmoji = { master: '⭐', elite: '🏆', standard: '💡' };
          return `${categoryEmoji[skill.category]} **${skill.name}** (${skill.category})\n   ${skill.description}\n   Triggers: ${skill.triggers.slice(0, 5).join(', ')}`;
        }).join('\n\n');

        const summary = `**Available Claude Code Skills (${filteredSkills.length} total)**\n\n${skillsList}\n\n**Usage:** Use \`apply_skill\` to activate a specific skill, or \`auto_skill_match\` to find the best skill automatically.`;

        return { content: [{ type: 'text', text: summary }] };
      }

      case 'find_skills': {
        const { query } = args as { query: string };
        const matchingSkills = skills.findMatchingSkills(query);

        if (matchingSkills.length === 0) {
          return { content: [{ type: 'text', text: `No skills found matching "${query}". Use \`list_skills\` to see all available skills.` }] };
        }

        const skillsList = matchingSkills.map(skill => {
          const categoryEmoji = { master: '⭐', elite: '🏆', standard: '💡' };
          return `${categoryEmoji[skill.category]} **${skill.name}** (${skill.category})\n   ${skill.description}`;
        }).join('\n\n');

        const result = `**Skills matching "${query}" (${matchingSkills.length} found)**\n\n${skillsList}\n\n**Next:** Use \`apply_skill\` with one of these skill names to activate it.`;

        return { content: [{ type: 'text', text: result }] };
      }

      case 'apply_skill': {
        const { skillName, task, context } = args as { skillName: string; task: string; context?: string };
        const result = await skills.applySkill(skillName, task, context);
        return { content: [{ type: 'text', text: result }] };
      }

      case 'auto_skill_match': {
        const { task, context } = args as { task: string; context?: string };
        const matchingSkills = skills.findMatchingSkills(task);

        if (matchingSkills.length === 0) {
          return { content: [{ type: 'text', text: `No skills automatically matched for "${task}". Try using \`find_skills\` with specific keywords, or \`list_skills\` to browse all available skills.` }] };
        }

        // Apply the best matching skill
        const bestSkill = matchingSkills[0];
        const result = await skills.applySkill(bestSkill.name, task, context);

        let response = `**🎯 AUTO-MATCHED SKILL: ${bestSkill.name.toUpperCase()}**\n\n`;

        if (matchingSkills.length > 1) {
          response += `*Also considered: ${matchingSkills.slice(1, 4).map(s => s.name).join(', ')}*\n\n`;
        }

        response += result;

        return { content: [{ type: 'text', text: response }] };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (err) {
    return {
      content: [{ type: 'text', text: `Error: ${errorMessage(err)}` }],
      isError: true,
    };
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