#!/usr/bin/env node

/**
 * Skill Doctor - CLI tool for validating skills before installation
 *
 * Performs comprehensive validation of skill manifests, security scanning,
 * trust assessment, and integrity checks.
 *
 * Usage:
 *   npm run skill:check ~/.claude/skills/verified/json-formatter/
 *   npm run skill:check ~/.claude/skills/untrusted/
 *   node scripts/skill-doctor.js /path/to/skill
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Color codes for output formatting
const colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    dim: '\x1b[2m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    white: '\x1b[37m'
};

// Trust levels
const TrustLevel = {
    VERIFIED: 'verified',
    UNTRUSTED: 'untrusted',
    BUILT_IN: 'built-in'
};

// Security patterns to scan for
const DANGEROUS_PATTERNS = [
    {
        pattern: /eval\s*\(/g,
        severity: 'critical',
        description: 'Dynamic code execution via eval()'
    },
    {
        pattern: /\.exec\s*\(/g,
        severity: 'critical',
        description: 'Command execution via exec()'
    },
    {
        pattern: /require\s*\(\s*[^'"][^)]*\)/g,
        severity: 'high',
        description: 'Dynamic require() calls'
    },
    {
        pattern: /import\s*\(\s*[^'"][^)]*\)/g,
        severity: 'high',
        description: 'Dynamic import() calls'
    },
    {
        pattern: /child_process|spawn|fork/g,
        severity: 'critical',
        description: 'Process creation/manipulation'
    },
    {
        pattern: /fs\.unlink|fs\.rmdir|fs\.rm/g,
        severity: 'high',
        description: 'File system deletion operations'
    },
    {
        pattern: /process\.env\[['"]\w+['"]\]\s*=/g,
        severity: 'medium',
        description: 'Environment variable modification'
    },
    {
        pattern: /fetch\s*\(\s*[^'"][^)]*\)/g,
        severity: 'medium',
        description: 'Dynamic URL fetching'
    },
    {
        pattern: /localStorage|sessionStorage/g,
        severity: 'low',
        description: 'Browser storage access'
    },
    {
        pattern: /document\.|window\.|global\./g,
        severity: 'medium',
        description: 'Global object access'
    }
];

// Manifest schema validation
const REQUIRED_FIELDS = [
    'name', 'version', 'author', 'created', 'updated', 'trust_level',
    'capabilities', 'required_permissions', 'resource_limits',
    'description', 'category', 'triggers'
];

const VALID_TRUST_LEVELS = Object.values(TrustLevel);
const VALID_CATEGORIES = ['standard', 'utility', 'development', 'security', 'experimental'];

class SkillDoctor {
    constructor() {
        this.results = {
            manifest: { valid: false, issues: [] },
            security: { threats: [], level: 'safe' },
            trust: { level: null, auto_approved: false, concerns: [] },
            integrity: { verified: false, hash: null, expected: null }
        };
    }

    /**
     * Main validation entry point
     */
    async validateSkill(skillPath) {
        const expandedPath = this.expandPath(skillPath);

        if (!fs.existsSync(expandedPath)) {
            throw new Error(`Skill path does not exist: ${expandedPath}`);
        }

        const isDirectory = fs.statSync(expandedPath).isDirectory();

        if (isDirectory) {
            return await this.validateDirectory(expandedPath);
        } else {
            // Treat as manifest file
            const dir = path.dirname(expandedPath);
            return await this.validateDirectory(dir);
        }
    }

    /**
     * Validate a skill directory
     */
    async validateDirectory(skillDir) {
        const skillName = path.basename(skillDir);
        const manifestPath = path.join(skillDir, 'skill-manifest.json');
        const skillPath = path.join(skillDir, 'skill.ts');
        const skillJsPath = path.join(skillDir, 'skill.js');

        // Reset results
        this.results = {
            manifest: { valid: false, issues: [] },
            security: { threats: [], level: 'safe' },
            trust: { level: null, auto_approved: false, concerns: [] },
            integrity: { verified: false, hash: null, expected: null }
        };

        // Validate manifest
        await this.validateManifest(manifestPath);

        // Find skill implementation
        const implementationPath = fs.existsSync(skillPath) ? skillPath :
                                   fs.existsSync(skillJsPath) ? skillJsPath : null;

        if (implementationPath) {
            // Security scan
            await this.performSecurityScan(implementationPath);

            // Integrity check
            await this.checkIntegrity(manifestPath, implementationPath);
        } else {
            this.results.security.threats.push({
                severity: 'medium',
                description: 'No skill implementation found (skill.ts or skill.js)'
            });
        }

        // Trust assessment
        await this.assessTrust(manifestPath);

        return {
            skillName,
            skillPath: skillDir,
            ...this.results
        };
    }

    /**
     * Validate skill manifest against schema
     */
    async validateManifest(manifestPath) {
        try {
            if (!fs.existsSync(manifestPath)) {
                this.results.manifest.issues.push('skill-manifest.json not found');
                return;
            }

            const manifestContent = fs.readFileSync(manifestPath, 'utf8');
            const manifest = JSON.parse(manifestContent);

            // Check required fields
            for (const field of REQUIRED_FIELDS) {
                if (!(field in manifest)) {
                    this.results.manifest.issues.push(`Missing required field: ${field}`);
                }
            }

            // Validate specific fields
            if (manifest.name && !/^[a-z0-9-]+$/.test(manifest.name)) {
                this.results.manifest.issues.push('Name must be lowercase, kebab-case');
            }

            if (manifest.version && !/^\d+\.\d+\.\d+$/.test(manifest.version)) {
                this.results.manifest.issues.push('Version must follow semantic versioning (x.y.z)');
            }

            if (manifest.trust_level && !VALID_TRUST_LEVELS.includes(manifest.trust_level)) {
                this.results.manifest.issues.push(`Invalid trust_level: ${manifest.trust_level}`);
            }

            if (manifest.category && !VALID_CATEGORIES.includes(manifest.category)) {
                this.results.manifest.issues.push(`Invalid category: ${manifest.category}`);
            }

            // Validate resource limits
            if (manifest.resource_limits) {
                const limits = manifest.resource_limits;

                if (typeof limits.max_memory_mb !== 'number' || limits.max_memory_mb <= 0) {
                    this.results.manifest.issues.push('max_memory_mb must be a positive number');
                }

                if (typeof limits.timeout_seconds !== 'number' || limits.timeout_seconds <= 0) {
                    this.results.manifest.issues.push('timeout_seconds must be a positive number');
                }

                if (typeof limits.max_network_requests !== 'number' || limits.max_network_requests < 0) {
                    this.results.manifest.issues.push('max_network_requests must be a non-negative number');
                }
            }

            // Validate permissions
            if (manifest.required_permissions) {
                const validPermissions = [
                    'read:text', 'write:text', 'read:file', 'write:file',
                    'network:fetch', 'network:dns', 'system:env'
                ];

                for (const perm of manifest.required_permissions) {
                    if (!validPermissions.includes(perm)) {
                        this.results.manifest.issues.push(`Unknown permission: ${perm}`);
                    }
                }
            }

            this.results.manifest.valid = this.results.manifest.issues.length === 0;
            this.results.manifest.data = manifest;

        } catch (error) {
            this.results.manifest.issues.push(`Failed to parse manifest: ${error.message}`);
        }
    }

    /**
     * Perform security scanning on skill implementation
     */
    async performSecurityScan(skillPath) {
        try {
            const skillContent = fs.readFileSync(skillPath, 'utf8');

            for (const { pattern, severity, description } of DANGEROUS_PATTERNS) {
                const matches = skillContent.match(pattern);
                if (matches) {
                    this.results.security.threats.push({
                        severity,
                        description,
                        occurrences: matches.length,
                        pattern: pattern.source
                    });
                }
            }

            // Determine overall security level
            const criticalThreats = this.results.security.threats.filter(t => t.severity === 'critical');
            const highThreats = this.results.security.threats.filter(t => t.severity === 'high');

            if (criticalThreats.length > 0) {
                this.results.security.level = 'dangerous';
            } else if (highThreats.length > 0) {
                this.results.security.level = 'risky';
            } else if (this.results.security.threats.length > 0) {
                this.results.security.level = 'caution';
            } else {
                this.results.security.level = 'safe';
            }

        } catch (error) {
            this.results.security.threats.push({
                severity: 'high',
                description: `Failed to scan implementation: ${error.message}`
            });
        }
    }

    /**
     * Assess trust level and approval requirements
     */
    async assessTrust(manifestPath) {
        if (!this.results.manifest.valid || !this.results.manifest.data) {
            this.results.trust.concerns.push('Cannot assess trust: invalid manifest');
            return;
        }

        const manifest = this.results.manifest.data;
        this.results.trust.level = manifest.trust_level;

        // Check if skill should be auto-approved
        if (manifest.trust_level === TrustLevel.VERIFIED) {
            // Verified skills should have no network access and minimal security threats
            const hasNetwork = manifest.required_permissions?.some(p => p.startsWith('network:'));
            const hasCriticalThreats = this.results.security.threats.some(t => t.severity === 'critical');

            if (hasNetwork) {
                this.results.trust.concerns.push('VERIFIED skill requires network access');
                this.results.trust.auto_approved = false;
            } else if (hasCriticalThreats) {
                this.results.trust.concerns.push('VERIFIED skill has critical security threats');
                this.results.trust.auto_approved = false;
            } else {
                this.results.trust.auto_approved = true;
            }
        } else if (manifest.trust_level === TrustLevel.UNTRUSTED) {
            this.results.trust.auto_approved = false;

            // List specific concerns for untrusted skills
            if (manifest.required_permissions?.includes('network:fetch')) {
                this.results.trust.concerns.push('Network requests to external domains');
            }

            if (manifest.required_permissions?.includes('write:file')) {
                this.results.trust.concerns.push('File system write access');
            }

            if (this.results.security.threats.length > 0) {
                this.results.trust.concerns.push('Security threats detected in implementation');
            }

            // Check resource limits
            const limits = manifest.resource_limits || {};
            if (limits.max_memory_mb > 512) {
                this.results.trust.concerns.push('High memory usage requested');
            }

            if (limits.max_network_requests > 10) {
                this.results.trust.concerns.push('High network request limit');
            }
        } else if (manifest.trust_level === TrustLevel.BUILT_IN) {
            this.results.trust.auto_approved = true;
        }
    }

    /**
     * Check skill integrity using hash verification
     */
    async checkIntegrity(manifestPath, skillPath) {
        try {
            const manifest = this.results.manifest.data;
            if (!manifest || !manifest.integrity_hash) {
                this.results.integrity.verified = false;
                this.results.integrity.expected = 'No integrity hash in manifest';
                return;
            }

            // Calculate actual hash of implementation + manifest
            const manifestContent = fs.readFileSync(manifestPath, 'utf8');
            const skillContent = fs.readFileSync(skillPath, 'utf8');

            // Create hash of combined content (manifest + implementation)
            const combined = manifestContent + skillContent;
            const actualHash = crypto.createHash('sha256').update(combined, 'utf8').digest('hex');

            this.results.integrity.hash = actualHash;
            this.results.integrity.expected = manifest.integrity_hash;
            this.results.integrity.verified = actualHash === manifest.integrity_hash;

        } catch (error) {
            this.results.integrity.verified = false;
            this.results.integrity.expected = `Error calculating hash: ${error.message}`;
        }
    }

    /**
     * Generate human-readable report
     */
    generateReport(validationResult) {
        const { skillName, skillPath, manifest, security, trust, integrity } = validationResult;

        let report = '';

        // Header
        const statusIcon = this.getOverallStatus(validationResult) === 'pass' ? '✅' : '⚠️';
        report += `${statusIcon} ${colors.bright}SKILL DOCTOR REPORT${colors.reset}\n`;
        report += '='.repeat(50) + '\n';
        report += `${colors.cyan}Skill:${colors.reset} ${skillName}\n`;
        report += `${colors.cyan}Path:${colors.reset} ${skillPath}\n\n`;

        // Manifest validation
        if (manifest.valid) {
            report += `${colors.green}✅ MANIFEST:${colors.reset} Valid\n`;
        } else {
            report += `${colors.red}❌ MANIFEST:${colors.reset} Invalid\n`;
            for (const issue of manifest.issues) {
                report += `${colors.dim}   - ${issue}${colors.reset}\n`;
            }
        }

        // Security scanning
        if (security.level === 'safe') {
            report += `${colors.green}✅ SECURITY:${colors.reset} No threats detected\n`;
        } else {
            const icon = security.level === 'dangerous' ? '❌' : '⚠️';
            const color = security.level === 'dangerous' ? colors.red : colors.yellow;
            report += `${color}${icon} SECURITY:${colors.reset} ${this.capitalizeFirst(security.level)} (${security.threats.length} issues)\n`;

            for (const threat of security.threats.slice(0, 3)) { // Show top 3 threats
                const severityColor = threat.severity === 'critical' ? colors.red :
                                     threat.severity === 'high' ? colors.yellow : colors.blue;
                report += `${colors.dim}   - ${severityColor}${threat.severity.toUpperCase()}${colors.reset}${colors.dim}: ${threat.description}${colors.reset}\n`;
            }

            if (security.threats.length > 3) {
                report += `${colors.dim}   ... and ${security.threats.length - 3} more${colors.reset}\n`;
            }
        }

        // Trust assessment
        if (trust.auto_approved) {
            const trustLabel = trust.level === 'verified' ? 'VERIFIED (auto-approved)' : 'TRUSTED';
            report += `${colors.green}✅ TRUST:${colors.reset} ${trustLabel}\n`;
        } else {
            const color = trust.level === 'untrusted' ? colors.yellow : colors.red;
            report += `${color}⚠️ TRUST:${colors.reset} ${trust.level?.toUpperCase() || 'UNKNOWN'} (requires approval)\n`;

            if (trust.concerns.length > 0) {
                report += '\n' + `${colors.yellow}CONCERNS:${colors.reset}\n`;
                for (const concern of trust.concerns) {
                    report += `${colors.dim}- ${concern}${colors.reset}\n`;
                }
            }
        }

        // Integrity check
        if (integrity.verified) {
            report += `${colors.green}✅ INTEGRITY:${colors.reset} SHA256 verified\n`;
        } else {
            report += `${colors.yellow}⚠️ INTEGRITY:${colors.reset} Hash mismatch or missing\n`;
            if (integrity.hash && integrity.expected) {
                report += `${colors.dim}   Expected: ${integrity.expected}${colors.reset}\n`;
                report += `${colors.dim}   Actual:   ${integrity.hash}${colors.reset}\n`;
            } else {
                report += `${colors.dim}   ${integrity.expected}${colors.reset}\n`;
            }
        }

        // Overall verdict
        report += '\n';
        const overall = this.getOverallStatus(validationResult);
        if (overall === 'pass') {
            report += `${colors.bright}${colors.green}VERDICT: ✅ READY FOR INSTALLATION${colors.reset}\n`;
        } else {
            report += `${colors.bright}${colors.yellow}VERDICT: ⚠️ REQUIRES MANUAL REVIEW${colors.reset}\n`;
        }

        return report;
    }

    /**
     * Determine overall status
     */
    getOverallStatus(result) {
        if (!result.manifest.valid) return 'fail';
        if (result.security.level === 'dangerous') return 'fail';
        if (!result.trust.auto_approved) return 'review';
        if (result.security.threats.length > 0) return 'review';
        return 'pass';
    }

    /**
     * Capitalize first letter
     */
    capitalizeFirst(str) {
        return str.charAt(0).toUpperCase() + str.slice(1);
    }

    /**
     * Expand tilde and relative paths
     */
    expandPath(inputPath) {
        if (inputPath.startsWith('~')) {
            const home = process.env.HOME || process.env.USERPROFILE;
            return path.join(home, inputPath.slice(1));
        }
        return path.resolve(inputPath);
    }

    /**
     * Scan directory for multiple skills
     */
    async scanDirectory(dirPath) {
        const results = [];
        const items = fs.readdirSync(dirPath, { withFileTypes: true });

        for (const item of items) {
            if (item.isDirectory()) {
                const skillPath = path.join(dirPath, item.name);
                const manifestPath = path.join(skillPath, 'skill-manifest.json');

                if (fs.existsSync(manifestPath)) {
                    try {
                        const result = await this.validateSkill(skillPath);
                        results.push(result);
                    } catch (error) {
                        results.push({
                            skillName: item.name,
                            skillPath,
                            error: error.message
                        });
                    }
                }
            }
        }

        return results;
    }
}

// CLI Interface
async function main() {
    const args = process.argv.slice(2);

    if (args.length === 0) {
        console.log(`${colors.cyan}Skill Doctor${colors.reset} - Validate skills before installation\n`);
        console.log(`${colors.bright}Usage:${colors.reset}`);
        console.log(`  node scripts/skill-doctor.js <skill-path>`);
        console.log(`  npm run skill:check <skill-path>\n`);
        console.log(`${colors.bright}Examples:${colors.reset}`);
        console.log(`  skill:check ~/.claude/skills/verified/json-formatter/`);
        console.log(`  skill:check ~/.claude/skills/untrusted/`);
        console.log(`  skill:check /path/to/my-skill/`);
        process.exit(1);
    }

    const targetPath = args[0];
    const doctor = new SkillDoctor();

    try {
        const expandedPath = doctor.expandPath(targetPath);

        if (!fs.existsSync(expandedPath)) {
            console.error(`${colors.red}Error:${colors.reset} Path does not exist: ${expandedPath}`);
            process.exit(1);
        }

        const isDirectory = fs.statSync(expandedPath).isDirectory();

        if (isDirectory) {
            // Check if it's a single skill directory or contains multiple skills
            const manifestPath = path.join(expandedPath, 'skill-manifest.json');

            if (fs.existsSync(manifestPath)) {
                // Single skill validation
                const result = await doctor.validateSkill(expandedPath);
                const report = doctor.generateReport(result);
                console.log(report);

                const status = doctor.getOverallStatus(result);
                process.exit(status === 'pass' ? 0 : 1);
            } else {
                // Multiple skills directory
                console.log(`${colors.cyan}🔍 Scanning directory for skills...${colors.reset}\n`);
                const results = await doctor.scanDirectory(expandedPath);

                if (results.length === 0) {
                    console.log(`${colors.yellow}No skills found in ${expandedPath}${colors.reset}`);
                    process.exit(0);
                }

                let allPassed = true;

                for (let i = 0; i < results.length; i++) {
                    const result = results[i];

                    if (result.error) {
                        console.log(`${colors.red}❌ ${result.skillName}: ${result.error}${colors.reset}`);
                        allPassed = false;
                    } else {
                        const report = doctor.generateReport(result);
                        console.log(report);

                        if (doctor.getOverallStatus(result) !== 'pass') {
                            allPassed = false;
                        }
                    }

                    if (i < results.length - 1) {
                        console.log('\n' + '-'.repeat(50) + '\n');
                    }
                }

                console.log(`\n${colors.bright}SUMMARY:${colors.reset} ${results.length} skills checked`);
                process.exit(allPassed ? 0 : 1);
            }
        } else {
            console.error(`${colors.red}Error:${colors.reset} Path must be a directory containing skills`);
            process.exit(1);
        }

    } catch (error) {
        console.error(`${colors.red}Error:${colors.reset} ${error.message}`);
        process.exit(1);
    }
}

// Export for testing
export { SkillDoctor, TrustLevel, DANGEROUS_PATTERNS };

// Run if called directly
if (process.argv[1] === fileURLToPath(import.meta.url)) {
    main().catch(console.error);
}