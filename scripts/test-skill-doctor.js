#!/usr/bin/env node

/**
 * Test script for Skill Doctor
 *
 * Validates the skill doctor against the example skills
 */

import { SkillDoctor } from './skill-doctor.js';
import fs from 'fs';
import path from 'path';

async function runTests() {
    console.log('🧪 Testing Skill Doctor\n');

    const doctor = new SkillDoctor();
    const homeDir = process.env.HOME || process.env.USERPROFILE;
    const skillsDir = path.join(homeDir, '.claude', 'skills');

    // Test 1: Validate VERIFIED skill (json-formatter)
    console.log('Test 1: VERIFIED skill (json-formatter)');
    console.log('----------------------------------------');

    try {
        const jsonFormatterPath = path.join(skillsDir, 'verified', 'json-formatter');
        if (fs.existsSync(jsonFormatterPath)) {
            const result = await doctor.validateSkill(jsonFormatterPath);
            const report = doctor.generateReport(result);
            console.log(report);

            // Assertions
            if (!result.manifest.valid) {
                console.log('❌ FAIL: Manifest should be valid');
            }

            if (result.security.level !== 'safe') {
                console.log('❌ FAIL: Security level should be safe');
            }

            if (!result.trust.auto_approved) {
                console.log('❌ FAIL: Should be auto-approved');
            }

            console.log('✅ Test 1 completed\n');
        } else {
            console.log('⚠️ SKIP: json-formatter not found\n');
        }
    } catch (error) {
        console.log(`❌ ERROR: ${error.message}\n`);
    }

    // Test 2: Validate UNTRUSTED skill (url-checker)
    console.log('Test 2: UNTRUSTED skill (url-checker)');
    console.log('-------------------------------------');

    try {
        const urlCheckerPath = path.join(skillsDir, 'untrusted', 'url-checker');
        if (fs.existsSync(urlCheckerPath)) {
            const result = await doctor.validateSkill(urlCheckerPath);
            const report = doctor.generateReport(result);
            console.log(report);

            // Assertions
            if (!result.manifest.valid) {
                console.log('❌ FAIL: Manifest should be valid');
            }

            if (result.trust.auto_approved) {
                console.log('❌ FAIL: Should NOT be auto-approved');
            }

            if (result.trust.concerns.length === 0) {
                console.log('❌ FAIL: Should have trust concerns');
            }

            console.log('✅ Test 2 completed\n');
        } else {
            console.log('⚠️ SKIP: url-checker not found\n');
        }
    } catch (error) {
        console.log(`❌ ERROR: ${error.message}\n`);
    }

    // Test 3: Batch validation
    console.log('Test 3: Batch validation');
    console.log('------------------------');

    try {
        const verifiedDir = path.join(skillsDir, 'verified');
        if (fs.existsSync(verifiedDir)) {
            const results = await doctor.scanDirectory(verifiedDir);
            console.log(`Found ${results.length} skills in verified directory`);

            for (const result of results) {
                if (result.error) {
                    console.log(`❌ ${result.skillName}: ${result.error}`);
                } else {
                    const status = doctor.getOverallStatus(result);
                    const icon = status === 'pass' ? '✅' : '⚠️';
                    console.log(`${icon} ${result.skillName}: ${status}`);
                }
            }

            console.log('✅ Test 3 completed\n');
        } else {
            console.log('⚠️ SKIP: verified directory not found\n');
        }
    } catch (error) {
        console.log(`❌ ERROR: ${error.message}\n`);
    }

    console.log('🎉 All tests completed!');
}

if (process.argv[1].endsWith('test-skill-doctor.js')) {
    runTests().catch(console.error);
}

export { runTests };