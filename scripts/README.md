# Skill Doctor CLI

A comprehensive CLI tool for validating Claude skills before installation. Think of it as a "linter" for AI skills that checks manifests, scans for security issues, and assesses trust levels.

## 🚀 Quick Start

```bash
# Install dependencies (if any)
npm install

# Check a single skill
npm run skill:check ~/.claude/skills/verified/json-formatter/

# Check all skills in a directory
npm run skill:check ~/.claude/skills/verified/

# Run all validation tests
npm run skill:scan

# Test the skill doctor itself
npm run skill:test-doctor
```

## 📋 Features

### ✅ Manifest Validation
- **Schema compliance**: Validates against skill manifest schema
- **Required fields**: Ensures all mandatory fields are present
- **Data types**: Validates field types and formats
- **Resource limits**: Checks memory, timeout, and network constraints
- **Permissions**: Validates permission strings

### 🔒 Security Scanning
- **Pattern detection**: Scans for dangerous code patterns
- **Risk assessment**: Categorizes threats by severity level
- **Safe practices**: Identifies secure vs risky implementations
- **Network analysis**: Validates network permission usage

### 🛡️ Trust Assessment
- **Auto-approval logic**: Determines if skill can be auto-approved
- **Risk factors**: Identifies trust concerns and approval requirements
- **Trust levels**: Validates VERIFIED vs UNTRUSTED classification
- **Permission analysis**: Assesses permission requests vs trust level

### 🔐 Integrity Checking
- **Hash verification**: Validates SHA256 integrity hashes
- **Tampering detection**: Identifies modified skill files
- **Signature validation**: Checks digital signatures (if present)

## 📊 Output Format

### ✅ Ready for Installation
```
✅ SKILL DOCTOR REPORT
======================
Skill: json-formatter
Path: /path/to/skill

✅ MANIFEST: Valid
✅ SECURITY: No threats detected
✅ TRUST: VERIFIED (auto-approved)
✅ INTEGRITY: SHA256 verified

VERDICT: ✅ READY FOR INSTALLATION
```

### ⚠️ Requires Review
```
⚠️ SKILL DOCTOR REPORT
======================
Skill: url-checker
Path: /path/to/skill

✅ MANIFEST: Valid
⚠️ SECURITY: Caution (2 issues)
   - MEDIUM: Network requests to external domains
   - LOW: URL parsing with user input
⚠️ TRUST: UNTRUSTED (requires approval)

CONCERNS:
- Network requests to external domains
- High network request limit

VERDICT: ⚠️ REQUIRES MANUAL REVIEW
```

## 🔧 CLI Usage

### Basic Commands

```bash
# Check single skill
npm run skill:check ~/.claude/skills/verified/json-formatter/

# Check directory of skills
npm run skill:check ~/.claude/skills/untrusted/

# Use full path to script
node scripts/skill-doctor.js /path/to/skill

# Windows batch wrapper
scripts\skill-check.bat "C:\Users\user\.claude\skills\verified\json-formatter"
```

### Batch Operations

```bash
# Scan all example skills
npm run skill:scan

# Run basic verification checks
npm run skill:verify-examples

# Test complete skill loading lifecycle
npm run skill:test-lifecycle
```

### Exit Codes

- **0**: All skills passed validation
- **1**: One or more skills failed or require review

## 🔍 Security Patterns Detected

### 🚨 Critical Threats
- `eval()` - Dynamic code execution
- `exec()` - Command execution
- Process creation/manipulation
- File system deletion operations

### ⚠️ High Risk
- Dynamic `require()` calls
- Dynamic `import()` calls
- File system deletion

### 🔶 Medium Risk
- Environment variable modification
- Dynamic URL fetching
- Global object access

### 🔵 Low Risk
- Browser storage access
- Static imports
- Safe API usage

## 📋 Manifest Schema

### Required Fields
```json
{
  "name": "skill-name",                    // kebab-case identifier
  "version": "1.0.0",                      // semantic versioning
  "author": "Author Name",                 // creator identification
  "created": "2026-02-09T22:46:00Z",       // ISO 8601 timestamp
  "updated": "2026-02-09T22:46:00Z",       // ISO 8601 timestamp
  "trust_level": "verified|untrusted",     // trust classification
  "integrity_hash": "sha256...",           // content hash
  "capabilities": [],                      // skill functions
  "required_permissions": [],              // access requirements
  "resource_limits": {},                   // security constraints
  "description": "What this skill does",   // human description
  "category": "standard",                  // skill category
  "triggers": []                          // activation phrases
}
```

### Trust Level Guidelines

**VERIFIED** ✅:
- No network access required
- File operations limited to temp directories
- Memory limit ≤ 512MB
- Timeout ≤ 2 minutes
- Digital signature required
- Auto-approved for installation

**UNTRUSTED** ⚠️:
- May require network access (restricted domains)
- Memory limit ≤ 256MB
- Timeout ≤ 1 minute
- User approval required
- Sandboxed execution

## 🧪 Testing

### Run Built-in Tests
```bash
# Test the skill doctor against example skills
npm run skill:test-doctor

# Test individual components
npm test
```

### Test Example Skills
```bash
# Verify example skills are properly configured
npm run skill:verify-examples

# Test complete skill loading lifecycle
npm run skill:test-lifecycle
```

## 🔧 Integration

### As Pre-commit Hook
```bash
#!/bin/bash
# .git/hooks/pre-commit
npm run skill:check ~/.claude/skills/verified/
npm run skill:check ~/.claude/skills/untrusted/
```

### CI/CD Pipeline
```yaml
# .github/workflows/validate-skills.yml
name: Validate Skills
on: [push, pull_request]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - uses: actions/setup-node@v3
      with:
        node-version: '18'
    - run: npm install
    - run: npm run skill:scan
```

### MCP Server Integration
```javascript
// Add validation step to skill loader
import { SkillDoctor } from './scripts/skill-doctor.js';

const doctor = new SkillDoctor();
const result = await doctor.validateSkill(skillPath);

if (doctor.getOverallStatus(result) !== 'pass') {
    throw new Error(`Skill validation failed: ${result.skillName}`);
}
```

## 🚨 Troubleshooting

### Common Issues

**"Manifest not found"**
- Ensure `skill-manifest.json` exists in skill directory
- Check file permissions and path

**"Hash mismatch"**
- Recalculate integrity hash after code changes
- Use: `cat skill.ts skill-manifest.json | shasum -a 256`

**"Permission validation failed"**
- Check permission strings against valid list
- Ensure permissions match trust level requirements

**"Security threats detected"**
- Review flagged code patterns
- Use safer alternative APIs
- Consider lowering trust level

### Debug Mode
```bash
# Enable verbose logging
DEBUG=skill-doctor npm run skill:check /path/to/skill

# Show all security patterns
node scripts/skill-doctor.js --verbose /path/to/skill
```

## 📚 Related Tools

- **verify-examples.sh** - Basic shell script validation
- **test-skill-loading.js** - Full lifecycle testing
- **SkillLoader** - Runtime skill loading system
- **SkillRegistry** - Skill management and execution

## 🤝 Contributing

1. Add new security patterns to `DANGEROUS_PATTERNS`
2. Enhance manifest validation rules
3. Improve trust assessment logic
4. Add new output formats (JSON, XML, etc.)

## 📖 References

- [Skill Examples Guide](../.claude/skills/SKILL_EXAMPLES_GUIDE.md)
- [Skill Loading System Documentation](../.claude/skills/README.md)
- [Security Best Practices for AI Skills](https://docs.anthropic.com/en/docs/build-with-claude/skills-security)