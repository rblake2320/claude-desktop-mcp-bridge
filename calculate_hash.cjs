const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

// Calculate skill integrity hash
function calculateSkillHash(skillDir) {
  const skillPath = path.join(skillDir, 'skill.ts');
  const manifestPath = path.join(skillDir, 'skill-manifest.json');

  // Read the content
  const skillContent = fs.readFileSync(skillPath, 'utf-8');
  let manifestContent = fs.readFileSync(manifestPath, 'utf-8');

  // Parse manifest and set placeholder hash for calculation
  const manifest = JSON.parse(manifestContent);
  manifest.integrity_hash = 'PLACEHOLDER';
  manifestContent = JSON.stringify(manifest, null, 2);

  // Calculate hash
  const hash = crypto.createHash('sha256')
    .update(skillContent)
    .update(manifestContent)
    .digest('hex');

  return hash;
}

const skillDir = process.argv[2];
if (!skillDir) {
  console.error('Usage: node calculate_hash.js <skill_directory>');
  process.exit(1);
}

const hash = calculateSkillHash(skillDir);
console.log(hash);