#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('Claude Desktop MCP Bridge Configuration Validator');
console.log('Checking your setup for common issues...\n');

// Check Node.js version
const nodeVersion = process.version;
const majorVersion = parseInt(nodeVersion.slice(1).split('.')[0]);
console.log('=== Node.js Version Check ===');
console.log(`Current Node.js version: ${nodeVersion}`);

if (majorVersion >= 18) {
  console.log('✅ Node.js version is compatible');
} else {
  console.log('❌ Node.js version is too old. Please upgrade to Node.js 18+');
  process.exit(1);
}

// Check project structure
console.log('\n=== Project Structure Validation ===');
const projectRoot = path.resolve(__dirname, '..');
const requiredFiles = [
  'dist/filesystem-bridge/server.js',
  'dist/shell-bridge/server.js', 
  'dist/skills-bridge/server.js',
  'package.json'
];

let allValid = true;
for (const file of requiredFiles) {
  const filePath = path.join(projectRoot, file);
  if (fs.existsSync(filePath)) {
    console.log(`✅ Found: ${file}`);
  } else {
    console.log(`❌ Missing: ${file}`);
    allValid = false;
  }
}

if (!allValid) {
  console.log('⚠️  Some required files are missing. Run "npm run build"');
}

// Check dependencies
console.log('\n=== Health Checks ===');
const nodeModulesPath = path.join(projectRoot, 'node_modules');
if (fs.existsSync(nodeModulesPath)) {
  console.log('✅ Dependencies are installed');
} else {
  console.log('⚠️  node_modules not found. Run "npm install"');
  allValid = false;
}

// Generate sample config
console.log('\n=== Sample Configuration Generation ===');

function getClaudeConfigPath() {
  const platform = os.platform();
  const homeDir = os.homedir();

  switch (platform) {
    case 'darwin':
      return path.join(homeDir, 'Library/Application Support/Claude/claude_desktop_config.json');
    case 'win32':
      return path.join(homeDir, 'AppData/Roaming/Claude/claude_desktop_config.json');
    case 'linux':
      return path.join(homeDir, '.config/Claude/claude_desktop_config.json');
    default:
      throw new Error(`Unsupported platform: ${platform}`);
  }
}

const normalizedProjectRoot = projectRoot.split(String.fromCharCode(92)).join("/");

const sampleConfig = {
  mcpServers: {
    'filesystem-bridge': {
      command: 'node',
      args: [`${normalizedProjectRoot}/dist/filesystem-bridge/server.js`],
      env: {
        ALLOWED_PATHS: 'C:/Users/techai/projects,C:/Users/techai/Documents,C:/Users/techai/claude-skills',
        READ_ONLY: 'false',
        MAX_FILE_SIZE: '10485760'
      }
    },
    'shell-bridge': {
      command: 'node', 
      args: [`${normalizedProjectRoot}/dist/shell-bridge/server.js`],
      env: {
        TIMEOUT: '120000',
        BLOCKED_COMMANDS: 'rm,rmdir,del,format,fdisk,mkfs,dd,shutdown,reboot'
      }
    },
    'skills-bridge': {
      command: 'node',
      args: [`${normalizedProjectRoot}/dist/skills-bridge/server.js`],
      env: {
        SKILLS_PATH: '~/.claude/skills/',
        TIMEOUT: '60000'
      }
    }
  }
};

const configPath = getClaudeConfigPath();
const outputPath = path.join(path.dirname(configPath), 'claude_desktop_config_sample.json');

try {
  const configDir = path.dirname(outputPath);
  if (!fs.existsSync(configDir)) {
    fs.mkdirSync(configDir, { recursive: true });
  }
  fs.writeFileSync(outputPath, JSON.stringify(sampleConfig, null, 2));
  console.log(`✅ Sample configuration written to: ${outputPath}`);
  
  console.log('\n📋 Next steps:');
  console.log('1. Review the sample configuration file');
  console.log('2. Update ALLOWED_PATHS to match your directories');
  console.log('3. Copy content to Claude Desktop config file');
  console.log('4. Restart Claude Desktop');
} catch (error) {
  console.log(`❌ Failed to write sample config: ${error.message}`);
  allValid = false;
}

// Check existing config
console.log('\n=== Configuration File Check ===');
console.log(`Config location: ${configPath}`);

if (fs.existsSync(configPath)) {
  try {
    const configContent = fs.readFileSync(configPath, 'utf-8');
    const config = JSON.parse(configContent);
    console.log('✅ Existing config file is valid JSON');
    
    if (config.mcpServers) {
      const serverCount = Object.keys(config.mcpServers).length;
      console.log(`ℹ️  Found ${serverCount} MCP servers configured`);
    } else {
      console.log('⚠️  No mcpServers section found in existing config');
    }
  } catch (error) {
    console.log(`❌ Config file has invalid JSON: ${error.message}`);
    allValid = false;
  }
} else {
  console.log('ℹ️  No existing config file found (this is normal for first setup)');
}

// Summary
console.log('\n=== Summary ===');
if (allValid) {
  console.log('✅ Validation completed! Setup should work correctly.');
  console.log('\n🚀 Ready to use:');
  console.log('1. Copy sample config to Claude Desktop');
  console.log('2. Restart Claude Desktop');
  console.log('3. Test with: list_skills command');
} else {
  console.log('⚠️  Issues found. Address them before proceeding.');
  console.log('🔧 Run "npm install" and "npm run build" first');
}

process.exit(allValid ? 0 : 1);
