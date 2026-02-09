#!/usr/bin/env node

/**
 * Test script for MCP bridge servers
 * Tests basic functionality before Claude Desktop integration
 */

const { spawn } = require('child_process');
const path = require('path');

async function testServer(serverPath, serverName) {
  console.log(`\n🔍 Testing ${serverName}...`);

  return new Promise((resolve) => {
    const server = spawn('node', [serverPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: {
        ...process.env,
        // Add default env vars
        ALLOWED_PATHS: 'C:/Users/techai,C:/Users/techai/claude-desktop-mcp-bridge',
        READ_ONLY: 'false',
        MAX_FILE_SIZE: '10485760',
        TIMEOUT: '30000',
        BLOCKED_COMMANDS: 'rm,rmdir,del,format,fdisk,mkfs,dd,shutdown,reboot,taskkill,net'
      }
    });

    let output = '';
    let errorOutput = '';

    server.stdout.on('data', (data) => {
      output += data.toString();
    });

    server.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });

    // Send a simple JSON-RPC initialization message
    const initMessage = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: {
          name: 'test-client',
          version: '1.0.0'
        }
      }
    }) + '\n';

    setTimeout(() => {
      server.stdin.write(initMessage);
    }, 100);

    setTimeout(() => {
      server.kill();

      if (output.includes('jsonrpc') || output.includes('capabilities') || output.includes('tools')) {
        console.log(`✅ ${serverName}: Started and responding to JSON-RPC`);
      } else if (errorOutput.includes('Error') || errorOutput.includes('error')) {
        console.log(`❌ ${serverName}: Error detected`);
        console.log(`   Error: ${errorOutput.slice(0, 100)}...`);
      } else {
        console.log(`⚠️  ${serverName}: Started but no clear JSON-RPC response`);
        console.log(`   Output: ${output.slice(0, 100)}...`);
      }

      resolve();
    }, 2000);

    server.on('error', (error) => {
      console.log(`❌ ${serverName}: Failed to start - ${error.message}`);
      resolve();
    });
  });
}

async function main() {
  console.log('🚀 Testing MCP Bridge Servers\n');

  const distDir = path.join(__dirname, 'dist');
  const filesystemServer = path.join(distDir, 'filesystem-bridge', 'server.js');
  const shellServer = path.join(distDir, 'shell-bridge', 'server.js');

  await testServer(filesystemServer, 'filesystem-bridge');
  await testServer(shellServer, 'shell-bridge');

  console.log('\n✨ Testing complete!');
  console.log('\nNext steps:');
  console.log('1. Restart Claude Desktop');
  console.log('2. Check that MCP tools appear in Claude Desktop');
  console.log('3. Follow the testing guide in MCP_BRIDGE_TESTING_GUIDE.md');
}

main().catch(console.error);