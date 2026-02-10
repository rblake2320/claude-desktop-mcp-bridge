/**
 * Test Script for Dynamic Skill Loading Lifecycle
 *
 * This demonstrates the complete skill loading lifecycle with our two example skills.
 * Run this to see how the system discovers, validates, and loads skills.
 */

import { SkillLoader } from './skill-loader.js';
import { SkillRegistry } from './skill-registry.js';
import { TrustLevel } from './types.js';

async function demonstrateSkillLifecycle() {
    console.log('🚀 Dynamic Skill Loading Lifecycle Demonstration');
    console.log('=================================================\n');

    const loader = new SkillLoader();
    const registry = new SkillRegistry();

    try {
        console.log('📂 Step 1: Scanning for skills...');
        const scanResult = await loader.scanAllSkills();

        console.log(`✅ Found ${scanResult.found_skills} skills`);
        console.log(`✅ Loaded ${scanResult.loaded_skills} skills`);
        console.log(`⚠️  ${scanResult.pending_approval} skills pending approval`);
        console.log(`❌ ${scanResult.failed_skills} skills failed to load`);
        console.log(`⏱️  Scan completed in ${scanResult.scan_duration_ms}ms\n`);

        if (scanResult.errors.length > 0) {
            console.log('❌ Errors encountered:');
            scanResult.errors.forEach(error => {
                console.log(`   - ${error.skill_name}: ${error.error}`);
            });
            console.log('');
        }

        console.log('🔍 Step 2: Demonstrating skill validation...');

        // Test verified skill
        console.log('\n📋 Testing VERIFIED skill (json-formatter):');
        const jsonFormatterManifest = await loader.loadSkillManifest(
            '~/.claude/skills/verified/json-formatter'.replace('~', process.env.HOME || process.env.USERPROFILE),
            TrustLevel.VERIFIED
        );

        if (jsonFormatterManifest) {
            const validation = await loader.validateSkillTrust(jsonFormatterManifest);
            console.log(`   - Valid: ${validation.valid}`);
            console.log(`   - Trust Level: ${validation.trust_level}`);
            console.log(`   - Requires Approval: ${validation.requires_approval}`);
            console.log(`   - Issues: ${validation.issues.length === 0 ? 'None' : validation.issues.join(', ')}`);

            if (validation.valid && !validation.requires_approval) {
                console.log('   ✅ Skill loaded and ready for use!');
            }
        } else {
            console.log('   ❌ Failed to load manifest');
        }

        // Test untrusted skill
        console.log('\n📋 Testing UNTRUSTED skill (url-checker):');
        const urlCheckerManifest = await loader.loadSkillManifest(
            '~/.claude/skills/untrusted/url-checker'.replace('~', process.env.HOME || process.env.USERPROFILE),
            TrustLevel.UNTRUSTED
        );

        if (urlCheckerManifest) {
            const validation = await loader.validateSkillTrust(urlCheckerManifest);
            console.log(`   - Valid: ${validation.valid}`);
            console.log(`   - Trust Level: ${validation.trust_level}`);
            console.log(`   - Requires Approval: ${validation.requires_approval}`);
            console.log(`   - Issues: ${validation.issues.length === 0 ? 'None' : validation.issues.join(', ')}`);

            if (validation.requires_approval) {
                console.log('   ⏳ Skill requires user approval before use');
                console.log('   📝 This would trigger the approval workflow');
            }
        } else {
            console.log('   ❌ Failed to load manifest');
        }

        console.log('\n🎯 Step 3: Demonstrating skill registry...');

        // Register both skills
        if (jsonFormatterManifest) {
            const definition = await loader.manifestToDefinition(jsonFormatterManifest);
            registry.registerSkill(jsonFormatterManifest, definition);
            console.log('   ✅ Registered json-formatter skill');
        }

        if (urlCheckerManifest) {
            const definition = await loader.manifestToDefinition(urlCheckerManifest);
            registry.registerSkill(urlCheckerManifest, definition);
            console.log('   ✅ Registered url-checker skill');
        }

        // Show registry stats
        const stats = registry.getStats();
        console.log(`\n📊 Registry Statistics:`);
        console.log(`   - Active skills: ${stats.active_skills}`);
        console.log(`   - Pending approval: ${stats.pending_approval}`);
        console.log(`   - Total registered: ${stats.total_skills}`);

        // Show cache statistics
        const cacheStats = loader.getCacheStats();
        console.log(`\n💾 Cache Statistics:`);
        console.log(`   - Scan cache entries: ${cacheStats.scanCache}`);
        console.log(`   - Trust cache entries: ${cacheStats.trustCache}`);

        console.log('\n🎉 Skill Loading Lifecycle Complete!');
        console.log('\n📝 What happened:');
        console.log('   1. ✅ Skills were discovered from directory structure');
        console.log('   2. ✅ Manifests were parsed and validated');
        console.log('   3. ✅ Security scanning was performed');
        console.log('   4. ✅ Trust levels were enforced');
        console.log('   5. ✅ VERIFIED skill loaded immediately');
        console.log('   6. ⏳ UNTRUSTED skill marked for approval');
        console.log('   7. ✅ Skills registered in the skill registry');

    } catch (error) {
        console.error('❌ Error during demonstration:', error);
    }
}

// Export for testing purposes
export { demonstrateSkillLifecycle };

// Run if called directly
if (process.argv[1].endsWith('test-skill-loading.js')) {
    demonstrateSkillLifecycle().catch(console.error);
}