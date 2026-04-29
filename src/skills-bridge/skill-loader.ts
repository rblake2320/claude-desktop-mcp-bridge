/**
 * Dynamic skill loading with trust-based security validation
 * Phase 3A: SkillLoader for scanning and loading skills from directory structure
 */

import { readdir, readFile, access, lstat } from 'fs/promises';
import { join, sep } from 'path';
import { homedir } from 'os';
import { createHash } from 'node:crypto';
import {
  SkillManifest,
  SkillDefinition,
  TrustLevel,
  SkillCategory,
  SkillScanResult,
  TrustValidationResult,
  SKILL_DIRECTORIES,
  DANGEROUS_SKILL_PATTERNS,
  SKILL_NAME_PATTERN,
  SKILL_VERSION_PATTERN,
  MAX_SKILL_NAME_LENGTH,
  MAX_DESCRIPTION_LENGTH,
  MAX_TRIGGERS_COUNT,
  MAX_CAPABILITIES_COUNT,
  DEFAULT_RESOURCE_LIMITS
} from './types.js';

/**
 * Dynamic skill loader with trust-based validation and security scanning
 */
export class SkillLoader {
  private scanCache: Map<string, { lastScan: Date; result: SkillScanResult }> = new Map();
  private trustCache: Map<string, TrustValidationResult> = new Map();
  private cachedRootSkills: SkillManifest[] | null = null;

  constructor(private basePath: string = SKILL_DIRECTORIES.ROOT) {
    // Resolve ~ to actual home directory
    this.basePath = this.basePath.replace('~', homedir());
  }

  /**
   * Scan all skill directories for valid skills
   */
  async scanAllSkills(): Promise<SkillScanResult> {
    const startTime = Date.now();
    const errors: Array<{ skill_name: string; error: string; file_path: string }> = [];
    const foundSkills: SkillManifest[] = [];

    // Scan each trust level directory (skill-manifest.json + skill.ts format)
    const directories = [
      { path: SKILL_DIRECTORIES.BUILTIN, trustLevel: TrustLevel.BUILT_IN },
      { path: SKILL_DIRECTORIES.VERIFIED, trustLevel: TrustLevel.VERIFIED },
      { path: SKILL_DIRECTORIES.UNTRUSTED, trustLevel: TrustLevel.UNTRUSTED }
    ];

    for (const { path, trustLevel } of directories) {
      try {
        const resolvedPath = path.replace('~', homedir());
        const skills = await this.scanDirectory(resolvedPath, trustLevel);
        foundSkills.push(...skills);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        errors.push({
          skill_name: 'directory_scan',
          error: `Failed to scan ${path}: ${errorMessage}`,
          file_path: path
        });
      }
    }

    // Scan root-level directories for SKILL.md format (Claude Code native skills)
    try {
      const rootSkills = await this.scanRootLevelSkills();
      // Only add skills not already found via manifest format
      const existingNames = new Set(foundSkills.map(s => s.name));
      for (const skill of rootSkills) {
        if (!existingNames.has(skill.name)) {
          foundSkills.push(skill);
        }
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      errors.push({
        skill_name: 'root_skill_scan',
        error: `Failed to scan root-level SKILL.md files: ${errorMessage}`,
        file_path: this.basePath
      });
    }

    // Validate all found skills
    let loadedSkills = 0;
    let pendingApproval = 0;

    for (const manifest of foundSkills) {
      try {
        const validation = await this.validateSkillTrust(manifest);
        if (validation.valid) {
          if (validation.requires_approval) {
            pendingApproval++;
          } else {
            loadedSkills++;
          }
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        errors.push({
          skill_name: manifest.name,
          error: `Validation failed: ${errorMessage}`,
          file_path: manifest.skill_file_path || 'unknown'
        });
      }
    }

    const result: SkillScanResult = {
      found_skills: foundSkills.length,
      loaded_skills: loadedSkills,
      failed_skills: errors.length,
      pending_approval: pendingApproval,
      scan_duration_ms: Date.now() - startTime,
      errors
    };

    // Cache the result
    this.scanCache.set(this.basePath, {
      lastScan: new Date(),
      result
    });

    return result;
  }

  /**
   * Scan a specific directory for skill manifests
   */
  async scanDirectory(dirPath: string, expectedTrustLevel: TrustLevel): Promise<SkillManifest[]> {
    const skills: SkillManifest[] = [];

    try {
      await access(dirPath);
      const entries = await readdir(dirPath, { withFileTypes: true });

      for (const entry of entries) {
        if (entry.isDirectory()) {
          const skillDir = join(dirPath, entry.name);
          try {
            const manifest = await this.loadSkillManifest(skillDir, expectedTrustLevel);
            if (manifest) {
              skills.push(manifest);
            }
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            console.error(`⚠️ Failed to load skill from ${skillDir}: ${errorMessage}`);
          }
        }
      }
    } catch (error) {
      const hasCode = error && typeof error === 'object' && 'code' in error;
      if (hasCode && (error as any).code !== 'ENOENT') {
        throw error;
      }
    }

    return skills;
  }

  /**
   * Load skill manifest from directory
   */
  async loadSkillManifest(skillDir: string, expectedTrustLevel: TrustLevel): Promise<SkillManifest | null> {
    const manifestPath = join(skillDir, 'skill-manifest.json');
    const skillPath = join(skillDir, 'skill.ts');

    try {
      // Check if required files exist
      await access(manifestPath);
      await access(skillPath);

      const manifestContent = await readFile(manifestPath, 'utf-8');
      const skillContent = await readFile(skillPath, 'utf-8');

      let manifest: SkillManifest;

      try {
        manifest = JSON.parse(manifestContent);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        throw new Error(`Invalid JSON in manifest: ${errorMessage}`);
      }

      // Validate manifest structure
      this.validateManifestStructure(manifest);

      // Calculate integrity hash
      const integrityHash = createHash('sha256')
        .update(skillContent)
        .update(manifestContent)
        .digest('hex');

      // Verify trust level matches directory
      if (manifest.trust_level !== expectedTrustLevel) {
        console.error(`⚠️ Trust level mismatch for ${manifest.name}: manifest=${manifest.trust_level}, directory=${expectedTrustLevel}`);
        manifest.trust_level = expectedTrustLevel; // Use directory trust level
      }

      // Add file paths and calculated hash
      manifest.skill_file_path = skillPath;
      manifest.manifest_path = manifestPath;
      manifest.integrity_hash = integrityHash;

      return manifest;

    } catch (error) {
      const hasCode = error && typeof error === 'object' && 'code' in error;
      if (hasCode && (error as any).code === 'ENOENT') {
        return null; // Skip directories without proper skill structure
      }
      throw error;
    }
  }

  /**
   * Convert manifest to skill definition for backwards compatibility
   */
  async manifestToDefinition(manifest: SkillManifest): Promise<SkillDefinition> {
    const skillContent = await readFile(manifest.skill_file_path!, 'utf-8');

    // Parse skill content to extract execution logic
    // This is a simplified parser - in production, you might use AST parsing
    const nameMatch = skillContent.match(/name:\s*['"](.*?)['"]/);
    const descMatch = skillContent.match(/description:\s*['"](.*?)['"]/);
    const triggersMatch = skillContent.match(/triggers:\s*\[(.*?)\]/s);
    const pairsWithMatch = skillContent.match(/pairsWith:\s*\[(.*?)\]/s);

    const definition: SkillDefinition = {
      name: nameMatch?.[1] || manifest.name,
      description: descMatch?.[1] || manifest.description,
      capabilities: manifest.capabilities,
      category: manifest.category,
      triggers: this.parseArrayString(triggersMatch?.[1] || ''),
      pairsWith: this.parseArrayString(pairsWithMatch?.[1] || ''),
      manifest,
      trust_level: manifest.trust_level,
      loaded_from_path: manifest.skill_file_path,
      last_loaded: new Date().toISOString()
    };

    return definition;
  }

  /**
   * Validate skill trust and security
   */
  async validateSkillTrust(manifest: SkillManifest): Promise<TrustValidationResult> {
    const cacheKey = `${manifest.name}_${manifest.integrity_hash}`;
    const cached = this.trustCache.get(cacheKey);

    if (cached) {
      return cached;
    }

    const issues: string[] = [];
    let requiresApproval = false;

    // 1. Validate manifest structure
    try {
      this.validateManifestStructure(manifest);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      issues.push(`Invalid manifest structure: ${errorMessage}`);
    }

    // 2. Security content scanning (skip for SKILL.md — markdown docs, not executable code)
    if (manifest.skill_file_path && !manifest.skill_file_path.endsWith('SKILL.md')) {
      try {
        const skillContent = await readFile(manifest.skill_file_path, 'utf-8');
        const securityIssues = this.scanForDangerousPatterns(skillContent);
        if (securityIssues.length > 0) {
          issues.push(...securityIssues);
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        issues.push(`Failed to read skill file: ${errorMessage}`);
      }
    }

    // 3. Trust level validation
    switch (manifest.trust_level) {
      case TrustLevel.BUILT_IN:
        // System skills must be in built-in directory or root-level SKILL.md skills
        if (manifest.skill_file_path &&
            !manifest.skill_file_path.includes(`${sep}built-in${sep}`) &&
            !manifest.manifest_path?.endsWith('SKILL.md')) {
          issues.push('System trust level only allowed for built-in or root-level skills');
        }
        break;

      case TrustLevel.VERIFIED:
        // Verified skills should have signature (placeholder for future signing)
        if (!manifest.signature) {
          issues.push('Verified skills should have digital signature');
        }
        break;

      case TrustLevel.UNTRUSTED:
        // Untrusted skills require approval
        requiresApproval = true;
        break;
    }

    // 4. Resource limit validation
    if (!manifest.resource_limits) {
      manifest.resource_limits = DEFAULT_RESOURCE_LIMITS[manifest.trust_level];
    }

    const result: TrustValidationResult = {
      valid: issues.length === 0,
      trust_level: manifest.trust_level,
      issues,
      requires_approval: requiresApproval,
      reason: issues.length > 0 ? issues.join('; ') : 'Validation passed'
    };

    // Cache the result
    this.trustCache.set(cacheKey, result);

    return result;
  }

  /**
   * Validate manifest structure against schema
   */
  private validateManifestStructure(manifest: SkillManifest): void {
    const required = ['name', 'version', 'author', 'trust_level', 'category', 'description', 'capabilities'];

    for (const field of required) {
      if (!(manifest as any)[field]) {
        throw new Error(`Missing required field: ${field}`);
      }
    }

    // Validate field constraints
    if (!SKILL_NAME_PATTERN.test(manifest.name)) {
      throw new Error('Invalid skill name format');
    }

    if (manifest.name.length > MAX_SKILL_NAME_LENGTH) {
      throw new Error('Skill name too long');
    }

    if (!SKILL_VERSION_PATTERN.test(manifest.version)) {
      throw new Error('Invalid version format (use semantic versioning)');
    }

    if (manifest.description.length > MAX_DESCRIPTION_LENGTH) {
      throw new Error('Description too long');
    }

    if (!Object.values(TrustLevel).includes(manifest.trust_level)) {
      throw new Error('Invalid trust level');
    }

    if (!Object.values(SkillCategory).includes(manifest.category)) {
      throw new Error('Invalid skill category');
    }

    if (manifest.triggers && manifest.triggers.length > MAX_TRIGGERS_COUNT) {
      throw new Error('Too many triggers');
    }

    if (manifest.capabilities.length > MAX_CAPABILITIES_COUNT) {
      throw new Error('Too many capabilities');
    }
  }

  /**
   * Scan skill content for dangerous patterns
   */
  private scanForDangerousPatterns(content: string): string[] {
    const issues: string[] = [];

    for (const pattern of DANGEROUS_SKILL_PATTERNS) {
      const match = content.match(pattern);
      if (match) {
        issues.push(`Potentially dangerous pattern detected: ${match[0]}`);
      }
    }

    // Additional security checks
    const suspiciousPatterns = [
      /eval\s*\(/,
      /Function\s*\(/,
      /\.exec\s*\(/,
      /child_process/,
      /fs\.unlink/,
      /fs\.rmdir/,
      /process\.env/,
      /require\s*\(\s*['""](?![@\w-])/,  // Dynamic requires
      /import\s*\(\s*['""][^'"]*['"]\s*\)/,  // Dynamic imports
    ];

    for (const pattern of suspiciousPatterns) {
      if (pattern.test(content)) {
        issues.push(`Suspicious pattern found: ${pattern.source}`);
      }
    }

    return issues;
  }

  /**
   * Parse array string from skill file
   */
  private parseArrayString(arrayStr: string): string[] {
    if (!arrayStr.trim()) return [];

    try {
      // Simple parser for array literals
      const items = arrayStr
        .split(',')
        .map(item => item.trim().replace(/['"]/g, ''))
        .filter(item => item.length > 0);

      return items;
    } catch (error) {
      console.error(`Failed to parse array string: ${arrayStr}`);
      return [];
    }
  }

  /**
   * Scan root-level skill directories for SKILL.md files (Claude Code native format).
   * These are loaded as BUILT_IN trust level.
   *
   * SKILL.md format: YAML front matter with `name` and `description` fields,
   * followed by markdown body with skill instructions.
   */
  async scanRootLevelSkills(): Promise<SkillManifest[]> {
    // Return cached results if available (avoids double-scanning during init)
    if (this.cachedRootSkills !== null) {
      return this.cachedRootSkills;
    }

    const skills: SkillManifest[] = [];
    const skipDirs = new Set(['built-in', 'verified', 'untrusted', '.cache', '.approvals']);

    try {
      await access(this.basePath);
      const entries = await readdir(this.basePath, { withFileTypes: true });

      for (const entry of entries) {
        if (!entry.isDirectory() || entry.name.startsWith('.') || skipDirs.has(entry.name)) {
          continue;
        }

        // Skip symlinked directories to prevent redirection attacks
        const fullEntryPath = join(this.basePath, entry.name);
        try {
          const entryStat = await lstat(fullEntryPath);
          if (entryStat.isSymbolicLink()) {
            console.error(`⚠️ Skipping symlinked skill directory: ${entry.name}`);
            continue;
          }
        } catch {
          continue;
        }

        const skillDir = fullEntryPath;
        const skillMdPath = join(skillDir, 'SKILL.md');

        try {
          // Reject symlinked SKILL.md files (directory symlinks already caught above)
          const fileLstat = await lstat(skillMdPath);
          if (fileLstat.isSymbolicLink()) {
            console.error(`⚠️ Skipping symlinked SKILL.md in ${entry.name}`);
            continue;
          }

          // Enforce max file size (1MB) to prevent memory exhaustion
          const fileStat = fileLstat;
          if (fileStat.size > 1024 * 1024) {
            console.error(`⚠️ SKILL.md too large (${fileStat.size} bytes) in ${skillDir}`);
            continue;
          }
          const content = await readFile(skillMdPath, 'utf-8');
          const frontMatter = this.parseSkillMdFrontMatter(content);

          if (!frontMatter.name || !frontMatter.description) {
            console.error(`⚠️ SKILL.md missing name/description in ${skillDir}`);
            continue;
          }

          // Validate skill name format
          if (!SKILL_NAME_PATTERN.test(frontMatter.name)) {
            console.error(`⚠️ Invalid skill name format in ${skillMdPath}: ${frontMatter.name}`);
            continue;
          }

          if (frontMatter.name.length > MAX_SKILL_NAME_LENGTH) {
            console.error(`⚠️ Skill name too long in ${skillMdPath}: ${frontMatter.name}`);
            continue;
          }

          // Derive triggers from the skill name (split on hyphens)
          const triggers = frontMatter.name.split('-').filter(t => t.length > 1);

          // Compute integrity hash from SKILL.md content
          const integrityHash = createHash('sha256').update(content).digest('hex');

          // Infer category from name patterns
          const category = this.inferCategory(frontMatter.name);

          const manifest: SkillManifest = {
            name: frontMatter.name,
            version: '1.0.0',
            author: 'Claude Skills Library',
            created: '2025-01-01T00:00:00Z',
            updated: new Date().toISOString(),
            trust_level: TrustLevel.BUILT_IN,
            integrity_hash: integrityHash,
            capabilities: [frontMatter.description],
            required_permissions: [],
            resource_limits: DEFAULT_RESOURCE_LIMITS[TrustLevel.BUILT_IN],
            description: frontMatter.description,
            category,
            triggers,
            pairs_with: [],
            skill_file_path: skillMdPath,
            manifest_path: skillMdPath,
          };

          skills.push(manifest);
        } catch (error) {
          // SKILL.md doesn't exist or can't be read — skip silently
          const hasCode = error && typeof error === 'object' && 'code' in error;
          if (hasCode && (error as any).code === 'ENOENT') continue;
          const errorMessage = error instanceof Error ? error.message : String(error);
          console.error(`⚠️ Error reading ${skillMdPath}: ${errorMessage}`);
        }
      }
    } catch (error) {
      const hasCode = error && typeof error === 'object' && 'code' in error;
      if (hasCode && (error as any).code !== 'ENOENT') {
        throw error;
      }
    }

    this.cachedRootSkills = skills;
    return skills;
  }

  /**
   * Clear the cached root-level skills (for rescan scenarios).
   */
  clearRootSkillsCache(): void {
    this.cachedRootSkills = null;
  }

  /**
   * Parse YAML front matter from a SKILL.md file.
   * Expected format:
   * ---
   * name: skill-name
   * description: "Skill description"
   * ---
   */
  private parseSkillMdFrontMatter(content: string): { name: string; description: string } {
    const result = { name: '', description: '' };

    // Match YAML front matter block between --- delimiters
    const fmMatch = content.match(/^---\s*\n([\s\S]*?)\n---/);
    if (!fmMatch) return result;

    const frontMatter = fmMatch[1];

    // Parse name field
    const nameMatch = frontMatter.match(/^name:\s*["']?(.+?)["']?\s*$/m);
    if (nameMatch) {
      result.name = nameMatch[1].trim();
    }

    // Parse description field (may be quoted, single-line only to avoid cross-field capture)
    const descMatch = frontMatter.match(/^description:\s*["']?(.+?)["']?\s*$/m);
    if (descMatch) {
      result.description = descMatch[1].trim();
      // Truncate if too long
      if (result.description.length > MAX_DESCRIPTION_LENGTH) {
        result.description = result.description.slice(0, MAX_DESCRIPTION_LENGTH - 1) + '…';
      }
    }

    return result;
  }

  /**
   * Infer skill category from its name.
   * Falls back to STANDARD if no pattern matches.
   */
  private inferCategory(name: string): SkillCategory {
    // Split on hyphens to get word-level tokens for matching
    const tokens = new Set(name.toLowerCase().split('-'));
    const n = name.toLowerCase();

    // Security-related (word-boundary matching to avoid "asterisk" matching "risk")
    if (tokens.has('security') || tokens.has('compliance') || tokens.has('guardrail') ||
        tokens.has('audit') || tokens.has('risk') || tokens.has('privacy')) {
      return SkillCategory.SECURITY;
    }
    // Development tools
    if (n.startsWith('ultra-') || tokens.has('frontend') || tokens.has('backend') ||
        tokens.has('fullstack') || tokens.has('css') || tokens.has('debugger') ||
        tokens.has('architect') || n === 'clean-code' || tokens.has('csharp')) {
      return SkillCategory.DEVELOPMENT;
    }
    // Utility / bridge tools
    if (tokens.has('bridge') || n === 'pdf' || n === 'pptx' ||
        n === 'docx' || n === 'xlsx' || tokens.has('theme') ||
        n === 'skill-creator') {
      return SkillCategory.UTILITY;
    }
    // Experimental
    if (tokens.has('experimental') || n === 'algorithmic-art' || n === 'slack-gif-creator') {
      return SkillCategory.EXPERIMENTAL;
    }
    return SkillCategory.STANDARD;
  }

  /**
   * Clear caches (for testing or refresh)
   */
  clearCache(): void {
    this.scanCache.clear();
    this.trustCache.clear();
    this.cachedRootSkills = null;
  }

  /**
   * Get cache statistics
   */
  getCacheStats(): { scanCache: number; trustCache: number } {
    return {
      scanCache: this.scanCache.size,
      trustCache: this.trustCache.size
    };
  }
}