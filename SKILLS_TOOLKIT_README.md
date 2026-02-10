# Claude Skills Toolkit

A comprehensive toolkit for validating, testing, and managing Claude skills with security-first design principles.

## 🚀 Overview

This toolkit provides essential tools for Claude skill development and deployment:

- **🩺 Skill Doctor**: CLI tool for comprehensive skill validation
- **🔒 Security Scanner**: Detects dangerous patterns and security risks
- **📋 Manifest Validator**: Schema validation and compliance checking
- **🛡️ Trust Assessor**: Determines approval requirements and risk levels
- **🔐 Integrity Checker**: Hash verification and tampering detection

## 📦 Installation

```bash
# Clone or navigate to the skills toolkit directory
cd /path/to/skills-toolkit

# Install dependencies (if any)
npm install

# Verify installation
npm run help
```

## 🩺 Skill Doctor CLI

The main tool for validating skills before installation.

### Quick Start

```bash
# Check a single skill
npm run skill:check ~/.claude/skills/verified/json-formatter/

# Check all skills in a directory
npm run skill:check ~/.claude/skills/verified/

# Batch scan all example skills
npm run skill:scan

# Test the doctor itself
npm run skill:test-doctor
```

### Example Output

**✅ Ready for Installation**:
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

**⚠️ Requires Review**:
```
⚠️ SKILL DOCTOR REPORT
======================
Skill: url-checker
Path: /path/to/skill

✅ MANIFEST: Valid
⚠️ SECURITY: Caution (2 issues)
⚠️ TRUST: UNTRUSTED (requires approval)

CONCERNS:
- Network requests to external domains
- High network request limit

VERDICT: ⚠️ REQUIRES MANUAL REVIEW
```

## 🔧 Available Commands

```bash
# Skill validation
npm run skill:check <path>        # Validate single skill or directory
npm run skill:doctor <path>       # Alias for skill:check
npm run skill:scan               # Validate all example skills

# Testing & verification
npm run skill:test-doctor        # Test the skill doctor tool
npm run skill:verify-examples    # Run basic shell verification
npm run skill:test-lifecycle     # Test complete skill loading

# Utilities
npm run help                     # Show available commands
npm test                         # Run all tests
```

## 📋 What Gets Validated

### ✅ Manifest Validation
- **Required fields**: name, version, author, trust_level, etc.
- **Schema compliance**: Data types, formats, and constraints
- **Resource limits**: Memory, timeout, network request limits
- **Permissions**: Valid permission strings and trust level alignment

### 🔒 Security Scanning
- **Critical threats**: `eval()`, `exec()`, process manipulation
- **High risk**: Dynamic imports, file system operations
- **Medium risk**: Environment modification, dynamic URLs
- **Low risk**: Storage access, static imports

### 🛡️ Trust Assessment
- **VERIFIED skills**: Auto-approved if no network access, no critical threats
- **UNTRUSTED skills**: Always require approval, strict limits enforced
- **Risk factors**: Network access, file operations, resource usage

### 🔐 Integrity Checking
- **SHA256 verification**: Validates manifest integrity hash
- **Tampering detection**: Identifies modified files
- **Content matching**: Ensures code matches expected hash

## 📊 Security Threat Levels

| Level | Examples | Action |
|-------|----------|---------|
| 🚨 **Critical** | `eval()`, `exec()`, process creation | ❌ Block installation |
| ⚠️ **High** | Dynamic imports, file deletion | ⚠️ Require review |
| 🔶 **Medium** | Env modification, dynamic URLs | ✅ Allow with warnings |
| 🔵 **Low** | Storage access, safe APIs | ✅ Allow |

## 🔧 Integration Examples

### Pre-commit Hook
```bash
#!/bin/bash
# .git/hooks/pre-commit
npm run skill:scan || exit 1
```

### CI/CD Pipeline
```yaml
name: Validate Skills
on: [push, pull_request]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - run: npm install
    - run: npm run skill:scan
```

### MCP Server Integration
```javascript
import { SkillDoctor } from './scripts/skill-doctor.js';

const doctor = new SkillDoctor();
const result = await doctor.validateSkill(skillPath);

if (doctor.getOverallStatus(result) === 'fail') {
    throw new Error(`Skill validation failed: ${result.skillName}`);
}
```

## 🧪 Testing

The toolkit includes comprehensive tests for validation logic:

```bash
# Test the skill doctor against example skills
npm run skill:test-doctor

# Run shell-based verification checks
npm run skill:verify-examples

# Test complete skill loading lifecycle
npm run skill:test-lifecycle
```

### Test Coverage
- ✅ Manifest parsing and validation
- ✅ Security pattern detection
- ✅ Trust level assessment
- ✅ Integrity hash verification
- ✅ Batch processing
- ✅ Error handling

## 📁 File Structure

```
scripts/
├── skill-doctor.js          # Main CLI tool
├── test-skill-doctor.js     # Test suite
├── skill-check.bat          # Windows batch wrapper
└── README.md               # Detailed documentation

package.json                # NPM scripts and dependencies
SKILLS_TOOLKIT_README.md    # This file
```

## 🚨 Troubleshooting

### Common Issues

**"Manifest not found"**
```bash
# Ensure skill-manifest.json exists
ls ~/.claude/skills/my-skill/skill-manifest.json
```

**"Hash mismatch"**
```bash
# Recalculate integrity hash
cat skill.ts skill-manifest.json | shasum -a 256
```

**"Permission validation failed"**
- Check permission strings against valid list
- Ensure permissions align with trust level

**"Security threats detected"**
- Review flagged patterns in implementation
- Use safer alternative APIs
- Consider lowering trust level to UNTRUSTED

### Debug Mode
```bash
# Enable verbose output (if implemented)
DEBUG=skill-doctor npm run skill:check /path/to/skill
```

## 🔗 Related Tools

- **verify-examples.sh**: Shell-based verification script
- **test-skill-loading.js**: Skill lifecycle testing
- **SkillLoader**: Runtime skill loading system
- **SkillRegistry**: Skill management and execution

## 📚 Documentation Links

- [Skill Examples Guide](/.claude/skills/SKILL_EXAMPLES_GUIDE.md)
- [Skills Directory README](/.claude/skills/README.md)
- [Detailed CLI Documentation](scripts/README.md)

## 🎯 Success Criteria

After running the toolkit, you should see:

1. ✅ **VERIFIED skills** pass all checks and auto-approve
2. ⚠️ **UNTRUSTED skills** are flagged for manual review
3. 🔍 Security scanning catches dangerous patterns
4. 📋 Manifest validation ensures schema compliance
5. 🔐 Integrity checking detects tampering

The toolkit provides the foundation for secure, reliable Claude skill deployment with comprehensive validation and security assessment.

---

*Built by the AI Army team for secure skill management and deployment.*