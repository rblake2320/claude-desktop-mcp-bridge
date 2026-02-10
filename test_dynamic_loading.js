#!/usr/bin/env node

import { SkillLoader } from './dist/skills-bridge/skill-loader.js';
import { SkillRegistry } from './dist/skills-bridge/skill-registry.js';
import { homedir } from 'os';

async function testDynamicLoading() {
  console.log('🧪 Testing Dynamic Skill Loading System...\n');

  try {
    // Initialize components
    const loader = new SkillLoader();
    const registry = new SkillRegistry();

    await registry.initialize();

    // Scan for skills
    console.log('📂 Scanning for skills...');
    const scanResult = await loader.scanAllSkills();

    console.log(`📊 Scan Results:`);
    console.log(`   Found: ${scanResult.found_skills} skills`);
    console.log(`   Loaded: ${scanResult.loaded_skills} skills`);
    console.log(`   Failed: ${scanResult.failed_skills} skills`);
    console.log(`   Pending approval: ${scanResult.pending_approval} skills`);
    console.log(`   Duration: ${scanResult.scan_duration_ms}ms`);

    if (scanResult.errors.length > 0) {
      console.log('\n❌ Errors encountered:');
      scanResult.errors.forEach(error => {
        console.log(`   ${error.skill_name}: ${error.error}`);
      });
    }

    // List skills in registry
    console.log('\n📋 Skills in registry:');
    const allSkills = registry.getSkills();
    allSkills.forEach(skill => {
      console.log(`   - ${skill.name} (${skill.trust_level})`);
    });

    // Test search functionality
    console.log('\n🔍 Testing search for "debug" skills:');
    const debugSkills = registry.findSkills('debug');
    debugSkills.forEach(skill => {
      console.log(`   - ${skill.name}: ${skill.description.substring(0, 80)}...`);
    });

    console.log('\n✅ Dynamic loading test completed successfully!');

  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    process.exit(0);
  }
}

testDynamicLoading();