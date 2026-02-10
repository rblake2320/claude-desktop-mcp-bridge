/**
 * SQLite-backed skill registry for persistent skill management
 * Phase 3A: Dynamic skill loading with trust-based security
 */

import { existsSync, mkdirSync } from 'fs';
import { dirname } from 'path';
import { homedir } from 'os';
import {
  SkillManifest,
  SkillDefinition,
  SkillRegistryEntry,
  TrustLevel,
  SKILL_DIRECTORIES
} from './types.js';

// Import Database type for typing (will be dynamically imported)
interface Database {
  prepare(sql: string): any;
  exec(sql: string): any;
  close(): void;
}

/**
 * SQLite-backed registry for managing skills with trust levels and metadata
 */
export class SkillRegistry {
  private db: Database | null = null;
  private dbPath: string;
  private skills: Map<string, SkillDefinition> = new Map();

  constructor() {
    // Resolve ~/.claude/skills path
    const skillsRoot = SKILL_DIRECTORIES.DATABASE.replace('~', homedir());
    this.dbPath = skillsRoot;
    this.ensureDirectoryStructure();
  }

  /**
   * Initialize the registry and create database schema
   */
  async initialize(): Promise<void> {
    try {
      // Dynamically import better-sqlite3 (if available)
      const Database = await this.importDatabase();
      this.db = new Database(this.dbPath);

      await this.createSchema();
      await this.loadSkillsFromDatabase();

      console.error(`✅ SkillRegistry initialized: ${this.skills.size} skills loaded`);
    } catch (error) {
      console.error(`⚠️ SQLite not available, using in-memory registry: ${error}`);
      // Fallback to in-memory operation
      this.db = null;
    }
  }

  /**
   * Dynamically import database library
   */
  private async importDatabase(): Promise<any> {
    // For Phase 3A, we'll skip SQLite to avoid compilation issues
    // Future versions can add proper dependency management
    throw new Error('SQLite database not available - running in memory-only mode');
  }

  /**
   * Create the database schema for skill management
   */
  private async createSchema(): Promise<void> {
    if (!this.db) return;

    const schema = `
      -- Skills registry table
      CREATE TABLE IF NOT EXISTS skills (
        id TEXT PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        manifest TEXT NOT NULL,
        definition TEXT NOT NULL,
        trust_level TEXT NOT NULL,
        category TEXT NOT NULL,
        registered_at TEXT NOT NULL,
        last_used TEXT,
        usage_count INTEGER DEFAULT 0,
        status TEXT DEFAULT 'active',
        file_path TEXT,
        integrity_hash TEXT
      );

      -- User approvals table
      CREATE TABLE IF NOT EXISTS user_approvals (
        id TEXT PRIMARY KEY,
        skill_name TEXT NOT NULL,
        trust_level TEXT NOT NULL,
        manifest TEXT NOT NULL,
        risk_assessment TEXT NOT NULL,
        requested_at TEXT NOT NULL,
        expires_at TEXT,
        approved BOOLEAN,
        approved_at TEXT
      );

      -- Skill usage analytics
      CREATE TABLE IF NOT EXISTS skill_usage (
        id TEXT PRIMARY KEY,
        skill_name TEXT NOT NULL,
        execution_time_ms INTEGER NOT NULL,
        success BOOLEAN NOT NULL,
        resources_used TEXT,
        executed_at TEXT NOT NULL
      );

      -- Create indexes for performance
      CREATE INDEX IF NOT EXISTS idx_skills_name ON skills(name);
      CREATE INDEX IF NOT EXISTS idx_skills_trust_level ON skills(trust_level);
      CREATE INDEX IF NOT EXISTS idx_skills_category ON skills(category);
      CREATE INDEX IF NOT EXISTS idx_approvals_skill ON user_approvals(skill_name);
      CREATE INDEX IF NOT EXISTS idx_usage_skill ON skill_usage(skill_name);
    `;

    this.db.exec(schema);
  }

  /**
   * Ensure the directory structure exists
   */
  private ensureDirectoryStructure(): void {
    const dirs = [
      SKILL_DIRECTORIES.ROOT,
      SKILL_DIRECTORIES.BUILTIN,
      SKILL_DIRECTORIES.VERIFIED,
      SKILL_DIRECTORIES.UNTRUSTED,
      SKILL_DIRECTORIES.CACHE,
      SKILL_DIRECTORIES.APPROVALS
    ];

    for (const dir of dirs) {
      const resolvedDir = dir.replace('~', homedir());
      if (!existsSync(resolvedDir)) {
        mkdirSync(resolvedDir, { recursive: true });
      }
    }

    // Create database directory
    const dbDir = dirname(this.dbPath);
    if (!existsSync(dbDir)) {
      mkdirSync(dbDir, { recursive: true });
    }
  }

  /**
   * Register a new skill in the registry
   */
  async registerSkill(manifest: SkillManifest, definition: SkillDefinition): Promise<void> {
    const entry: SkillRegistryEntry = {
      id: this.generateSkillId(manifest.name),
      name: manifest.name,
      manifest,
      definition,
      registered_at: new Date().toISOString(),
      usage_count: 0,
      status: manifest.trust_level === TrustLevel.UNTRUSTED ? 'pending_approval' : 'active'
    };

    // Store in memory
    this.skills.set(manifest.name, definition);

    // Store in database if available
    if (this.db) {
      try {
        const stmt = this.db.prepare(`
          INSERT OR REPLACE INTO skills (
            id, name, manifest, definition, trust_level, category,
            registered_at, usage_count, status, file_path, integrity_hash
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);

        stmt.run(
          entry.id,
          manifest.name,
          JSON.stringify(manifest),
          JSON.stringify(definition),
          manifest.trust_level,
          manifest.category,
          entry.registered_at,
          entry.usage_count,
          entry.status,
          manifest.skill_file_path || null,
          manifest.integrity_hash
        );
      } catch (error) {
        console.error(`Failed to store skill ${manifest.name} in database:`, error);
      }
    }
  }

  /**
   * Get skill by name
   */
  getSkill(name: string): SkillDefinition | null {
    return this.skills.get(name) || null;
  }

  /**
   * Get all skills, optionally filtered by trust level
   */
  getSkills(trustLevel?: TrustLevel): SkillDefinition[] {
    const skills = Array.from(this.skills.values());
    if (trustLevel) {
      return skills.filter(skill => skill.trust_level === trustLevel);
    }
    return skills;
  }

  /**
   * Find skills by search query
   */
  findSkills(query: string): SkillDefinition[] {
    const queryLower = query.toLowerCase();
    const skills = Array.from(this.skills.values());

    return skills.filter(skill => {
      // Check name match
      if (skill.name.toLowerCase().includes(queryLower)) return true;

      // Check description match
      if (skill.description.toLowerCase().includes(queryLower)) return true;

      // Check triggers match
      if (skill.triggers.some(trigger => trigger.toLowerCase().includes(queryLower))) return true;

      // Check capabilities match
      if (skill.capabilities.some(cap => cap.toLowerCase().includes(queryLower))) return true;

      return false;
    });
  }

  /**
   * Update skill trust level
   */
  async updateTrustLevel(skillName: string, newTrustLevel: TrustLevel): Promise<boolean> {
    const skill = this.skills.get(skillName);
    if (!skill) return false;

    skill.trust_level = newTrustLevel;

    // Update in database if available
    if (this.db) {
      try {
        const stmt = this.db.prepare(
          'UPDATE skills SET trust_level = ?, status = ? WHERE name = ?'
        );
        const status = newTrustLevel === TrustLevel.UNTRUSTED ? 'pending_approval' : 'active';
        stmt.run(newTrustLevel, status, skillName);
      } catch (error) {
        console.error(`Failed to update trust level for ${skillName}:`, error);
      }
    }

    return true;
  }

  /**
   * Record skill usage for analytics
   */
  async recordUsage(skillName: string, executionTimeMs: number, success: boolean): Promise<void> {
    // Update in-memory counter
    const skill = this.skills.get(skillName);
    if (skill && skill.manifest) {
      // Update usage count in database
      if (this.db) {
        try {
          // Update usage count
          const updateStmt = this.db.prepare(
            'UPDATE skills SET usage_count = usage_count + 1, last_used = ? WHERE name = ?'
          );
          updateStmt.run(new Date().toISOString(), skillName);

          // Record detailed usage analytics
          const insertStmt = this.db.prepare(`
            INSERT INTO skill_usage (id, skill_name, execution_time_ms, success, executed_at)
            VALUES (?, ?, ?, ?, ?)
          `);
          insertStmt.run(
            this.generateUsageId(),
            skillName,
            executionTimeMs,
            success,
            new Date().toISOString()
          );
        } catch (error) {
          console.error(`Failed to record usage for ${skillName}:`, error);
        }
      }
    }
  }

  /**
   * Get skill statistics
   */
  async getSkillStats(skillName?: string): Promise<any> {
    if (!this.db) return { error: 'Database not available' };

    try {
      if (skillName) {
        // Stats for specific skill
        const stmt = this.db.prepare(`
          SELECT
            s.name,
            s.trust_level,
            s.usage_count,
            s.last_used,
            COUNT(u.id) as total_executions,
            AVG(u.execution_time_ms) as avg_execution_time,
            SUM(CASE WHEN u.success = 1 THEN 1 ELSE 0 END) as successful_executions
          FROM skills s
          LEFT JOIN skill_usage u ON s.name = u.skill_name
          WHERE s.name = ?
          GROUP BY s.name
        `);
        return stmt.get(skillName);
      } else {
        // Overall stats
        const stmt = this.db.prepare(`
          SELECT
            COUNT(*) as total_skills,
            COUNT(CASE WHEN trust_level = 'system' THEN 1 END) as system_skills,
            COUNT(CASE WHEN trust_level = 'verified' THEN 1 END) as verified_skills,
            COUNT(CASE WHEN trust_level = 'untrusted' THEN 1 END) as untrusted_skills,
            SUM(usage_count) as total_usage
          FROM skills
        `);
        return stmt.get();
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      console.error('Failed to get skill stats:', error);
      return { error: errorMessage };
    }
  }

  /**
   * Load skills from database on initialization
   */
  private async loadSkillsFromDatabase(): Promise<void> {
    if (!this.db) return;

    try {
      const stmt = this.db.prepare('SELECT name, definition FROM skills WHERE status = "active"');
      const rows = stmt.all();

      for (const row of rows) {
        try {
          const definition = JSON.parse(row.definition);
          this.skills.set(row.name, definition);
        } catch (error) {
          console.error(`Failed to parse skill definition for ${row.name}:`, error);
        }
      }
    } catch (error) {
      console.error('Failed to load skills from database:', error);
    }
  }

  /**
   * Generate unique skill ID
   */
  private generateSkillId(name: string): string {
    return `skill_${name}_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
  }

  /**
   * Generate unique usage ID
   */
  private generateUsageId(): string {
    return `usage_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
  }

  /**
   * Close database connection
   */
  async close(): Promise<void> {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }

  /**
   * Export registry state for backup
   */
  async exportRegistry(): Promise<any> {
    const skills = Array.from(this.skills.entries()).map(([name, definition]) => ({
      name,
      definition,
      registered_at: new Date().toISOString()
    }));

    return {
      export_version: '1.0',
      export_date: new Date().toISOString(),
      skills_count: skills.length,
      skills
    };
  }

  /**
   * Import registry state from backup
   */
  async importRegistry(exportData: any): Promise<void> {
    if (!exportData.skills || !Array.isArray(exportData.skills)) {
      throw new Error('Invalid export data format');
    }

    for (const skillData of exportData.skills) {
      if (skillData.name && skillData.definition) {
        this.skills.set(skillData.name, skillData.definition);
      }
    }
  }
}