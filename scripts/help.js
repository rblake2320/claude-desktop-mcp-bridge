#!/usr/bin/env node

/**
 * Help script for Skills Toolkit
 */

console.log('📚 Claude Skills Toolkit Commands\n');

console.log('🩺 Skill Validation:');
console.log('  skill:check <path>     - Validate a skill or directory');
console.log('  skill:doctor <path>    - Alias for skill:check');
console.log('  skill:scan             - Validate all example skills');

console.log('\n🧪 Testing & Verification:');
console.log('  skill:test-doctor      - Test the skill doctor tool');
console.log('  skill:verify-examples  - Run basic shell verification');
console.log('  skill:test-lifecycle   - Test complete skill loading');

console.log('\n🔧 Utilities:');
console.log('  test                   - Run all tests');
console.log('  help                   - Show this help message');

console.log('\n📖 Examples:');
console.log('  npm run skill:check ~/.claude/skills/verified/json-formatter/');
console.log('  npm run skill:check ~/.claude/skills/untrusted/');
console.log('  npm run skill:scan');

console.log('\n🔗 Documentation:');
console.log('  SKILLS_TOOLKIT_README.md - Main toolkit documentation');
console.log('  scripts/README.md        - Detailed CLI documentation');
console.log('  ~/.claude/skills/SKILL_EXAMPLES_GUIDE.md - Skill development guide');