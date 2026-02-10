# Golden-Path Skill Examples Guide

This guide demonstrates the complete dynamic skill loading lifecycle with two concrete examples that anyone can follow.

## 📁 Directory Structure

```
~/.claude/skills/
├── verified/
│   └── json-formatter/              # ✅ VERIFIED trust level example
│       ├── skill-manifest.json     # Clean, complete manifest
│       └── skill.ts                # Simple JSON formatting skill
├── untrusted/
│   └── url-checker/                 # ⚠️ UNTRUSTED trust level example
│       ├── skill-manifest.json     # Manifest requiring approval
│       └── skill.ts                # URL validation skill
└── built-in/
    └── (existing legacy skills)
```

## 🎯 Example 1: VERIFIED Skill (json-formatter)

### Purpose
Demonstrates a **trusted, secure skill** that:
- ✅ Has VERIFIED trust level
- ✅ No network access required
- ✅ Safe operations only (JSON formatting)
- ✅ Loads immediately without approval

### Key Files

**skill-manifest.json**:
```json
{
  "name": "json-formatter",
  "version": "1.0.0",
  "author": "AI Army",
  "trust_level": "verified",
  "integrity_hash": "995bea...",
  "signature": "sha256:abc123def456...",
  "capabilities": ["json-format", "json-validate", "json-minify"],
  "required_permissions": ["read:text", "write:text"],
  "resource_limits": {
    "max_memory_mb": 64,
    "timeout_seconds": 30,
    "max_file_size_mb": 5,
    "max_network_requests": 0
  }
}
```

**skill.ts** highlights:
```typescript
// Clean, secure implementation
export const name = "json-formatter";
export const capabilities = ["json-format", "json-validate"];

export async function execute(args: string): Promise<string> {
  // Safe JSON operations only
  return formatJson(args);
}
```

### Usage
```bash
json-formatter format {"name":"John","age":30}
json-formatter validate {"test": "data"}
json-formatter minify {"a": 1, "b": 2}
```

## 🎯 Example 2: UNTRUSTED Skill (url-checker)

### Purpose
Demonstrates a **community skill** that:
- ⚠️ Has UNTRUSTED trust level
- ⚠️ Requires network access
- ⚠️ Needs user approval
- ⚠️ Has strict resource limits

### Key Files

**skill-manifest.json**:
```json
{
  "name": "url-checker",
  "version": "1.0.0",
  "author": "Community User",
  "trust_level": "untrusted",
  "required_permissions": ["network:fetch", "network:dns"],
  "resource_limits": {
    "max_memory_mb": 128,
    "timeout_seconds": 45,
    "max_network_requests": 5,
    "allowed_domains": ["api.safebrowsing.google.com"]
  }
}
```

**skill.ts** highlights:
```typescript
// Network-requiring functionality
export async function checkSafety(url: string): Promise<string> {
  // This would trigger approval workflow
  const analysis = await performUrlAnalysis(url);
  return formatSecurityReport(analysis);
}
```

### Approval Workflow
1. User tries to invoke: `url-checker https://example.com`
2. System detects UNTRUSTED + network permissions
3. Shows approval dialog with risk assessment
4. User must explicitly approve before execution

## 🚀 Testing the Lifecycle

### Step 1: Skill Discovery
```typescript
import { SkillLoader } from './skill-loader.js';

const loader = new SkillLoader();
const scanResult = await loader.scanAllSkills();

console.log(`Found ${scanResult.found_skills} skills`);
console.log(`${scanResult.pending_approval} need approval`);
```

### Step 2: Security Validation
```typescript
// VERIFIED skill - loads immediately
const jsonManifest = await loader.loadSkillManifest(
  '~/.claude/skills/verified/json-formatter',
  TrustLevel.VERIFIED
);
const validation = await loader.validateSkillTrust(jsonManifest);
// validation.requires_approval = false ✅

// UNTRUSTED skill - requires approval
const urlManifest = await loader.loadSkillManifest(
  '~/.claude/skills/untrusted/url-checker',
  TrustLevel.UNTRUSTED
);
const validation = await loader.validateSkillTrust(urlManifest);
// validation.requires_approval = true ⚠️
```

### Step 3: Skill Registration
```typescript
import { SkillRegistry } from './skill-registry.js';

const registry = new SkillRegistry();

// Register verified skill (immediate)
if (!validation.requires_approval) {
  const definition = await loader.manifestToDefinition(jsonManifest);
  registry.registerSkill(jsonManifest, definition);
}

// Register untrusted skill (pending approval)
const definition = await loader.manifestToDefinition(urlManifest);
registry.registerSkill(urlManifest, definition);
// Status: 'pending_approval'
```

## 📋 Manifest Guidelines

### Required Fields
```json
{
  "name": "skill-name",              // lowercase, kebab-case
  "version": "1.0.0",                // semantic versioning
  "author": "Your Name",             // skill creator
  "created": "2026-02-09T22:46:00Z", // ISO timestamp
  "updated": "2026-02-09T22:46:00Z", // ISO timestamp
  "trust_level": "verified|untrusted", // determines security
  "integrity_hash": "sha256...",     // calculated by system
  "capabilities": [...],             // what the skill can do
  "required_permissions": [...],     // what it needs access to
  "resource_limits": {...},          // security constraints
  "description": "...",              // clear explanation
  "category": "standard",            // skill category
  "triggers": [...],                 // activation phrases
  "pairs_with": [...]               // related skills
}
```

### Security Patterns

**VERIFIED Skills** ✅:
- No network access
- File operations limited to temp directories
- Memory limits: 512MB
- Timeout: 2 minutes
- Digital signature required

**UNTRUSTED Skills** ⚠️:
- Network access restricted to approved domains
- Memory limits: 256MB
- Timeout: 1 minute
- User approval required
- Sandboxed execution

## 🔒 Security Scanning

The system automatically scans for dangerous patterns:

```typescript
// Automatically flagged as dangerous:
eval(userInput)                    // Dynamic code execution
require(userInput)                 // Dynamic imports
fs.unlink('/system/file')         // File system manipulation
child_process.exec(command)       // Command execution
```

**Safe patterns**:
```typescript
JSON.parse(input)                 // Safe data parsing
input.replace(/pattern/, 'text')  // String manipulation
await fetch('https://api.example.com') // Limited network (if allowed)
```

## 🎨 Best Practices

### 1. Clean Manifests
- Use semantic versioning
- Clear, descriptive names
- Minimal required permissions
- Conservative resource limits

### 2. Secure Implementation
- Validate all inputs
- Use safe APIs only
- Handle errors gracefully
- No dynamic code execution

### 3. Clear Documentation
- Explain what the skill does
- Show usage examples
- Document any limitations
- Include help commands

### 4. Trust Level Guidelines

**Choose VERIFIED when**:
- Skill performs safe operations only
- No network access required
- Well-tested and validated
- Created by trusted developers

**Choose UNTRUSTED when**:
- Requires network access
- File system operations
- Community-contributed
- Experimental functionality

## 🚀 Quick Start

### Copy the Examples
```bash
# Copy to your skills directory
cp -r ~/.claude/skills/verified/json-formatter ~/.claude/skills/verified/my-skill
cp -r ~/.claude/skills/untrusted/url-checker ~/.claude/skills/untrusted/my-skill
```

### Modify for Your Use Case
1. Update `skill-manifest.json` with your details
2. Implement your logic in `skill.ts`
3. Calculate integrity hash: `cat skill.ts skill-manifest.json | sha256sum`
4. Update manifest with new hash
5. Test with skill loader

### Test the Lifecycle
```bash
node ~/.claude/skills/test-skill-loading.js
```

## 📊 Monitoring

### Check Discovery
```bash
# See what skills were found
curl -s http://localhost:3001/api/skills/scan | jq '.found_skills'
```

### Check Registry Status
```bash
# See registered skills
curl -s http://localhost:3001/api/skills/stats | jq
```

### Check Approval Queue
```bash
# See skills waiting for approval
curl -s http://localhost:3001/api/skills/pending | jq
```

---

## 🎉 Success Criteria

After following this guide, you should see:

1. ✅ **json-formatter** loads immediately (VERIFIED)
2. ⚠️ **url-checker** requires approval (UNTRUSTED)
3. 🔍 Security scanning validates both skills
4. 📋 Skills appear in registry with correct status
5. 🚀 Test script demonstrates full lifecycle

These examples provide the foundation for building your own skills with proper security and trust management.