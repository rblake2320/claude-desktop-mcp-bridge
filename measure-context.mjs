import { spawn } from 'child_process';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const serverPath = join(__dirname, 'dist', 'skills-bridge', 'server.js');

let nextId = 1;

function estimateTokens(text) {
  // Rough estimate: ~4 chars per token for English/JSON
  return Math.ceil(text.length / 4);
}

async function rpc(proc, method, params, timeoutMs = 25000) {
  const id = nextId++;
  return await new Promise((resolve, reject) => {
    let buf = '';
    const onData = (d) => {
      buf += d.toString('utf8');
      for (const line of buf.split(/\r?\n/)) {
        try {
          const parsed = JSON.parse(line);
          if (parsed.id === id) {
            proc.stdout.off('data', onData);
            clearTimeout(timer);
            resolve(parsed);
            return;
          }
        } catch {}
      }
    };
    proc.stdout.on('data', onData);
    proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    const timer = setTimeout(() => {
      proc.stdout.off('data', onData);
      reject(new Error(`Timeout: ${method} id=${id}`));
    }, timeoutMs);
  });
}

async function main() {
  const proc = spawn(process.execPath, [serverPath], {
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  let stderr = '';
  proc.stderr.on('data', d => { stderr += d.toString(); });

  try {
    await rpc(proc, 'initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'measure', version: '1.0' }
    });

    await new Promise(r => setTimeout(r, 6000));

    console.log('=== CONTEXT BURN MEASUREMENT ===\n');

    // 1. tools/list — this is loaded at MCP startup
    const toolsList = await rpc(proc, 'tools/list', {});
    const toolsJson = JSON.stringify(toolsList.result);
    const toolCount = toolsList.result?.tools?.length || 0;
    console.log(`1. TOOL SCHEMAS (tools/list at startup)`);
    console.log(`   Tools registered: ${toolCount}`);
    console.log(`   Response size: ${toolsJson.length} chars`);
    console.log(`   Est. tokens: ~${estimateTokens(toolsJson)}`);

    // Break down per tool
    console.log(`\n   Per-tool breakdown:`);
    let totalSchemaTokens = 0;
    for (const tool of (toolsList.result?.tools || [])) {
      const toolJson = JSON.stringify(tool);
      const tokens = estimateTokens(toolJson);
      totalSchemaTokens += tokens;
      console.log(`     ${tool.name}: ${toolJson.length} chars (~${tokens} tokens)`);
    }

    // 2. list_skills (compact, default)
    const listCompact = await rpc(proc, 'tools/call', { name: 'list_skills', arguments: {} });
    const listCompactText = listCompact.result?.content?.[0]?.text || '';
    console.log(`\n2. list_skills (compact/default)`);
    console.log(`   Response size: ${listCompactText.length} chars`);
    console.log(`   Est. tokens: ~${estimateTokens(listCompactText)}`);

    // 3. list_skills (verbose)
    const listVerbose = await rpc(proc, 'tools/call', { name: 'list_skills', arguments: { verbose: true } });
    const listVerboseText = listVerbose.result?.content?.[0]?.text || '';
    console.log(`\n3. list_skills (verbose=true)`);
    console.log(`   Response size: ${listVerboseText.length} chars`);
    console.log(`   Est. tokens: ~${estimateTokens(listVerboseText)}`);

    // 4. find_skills exact match
    const findExact = await rpc(proc, 'tools/call', { name: 'find_skills', arguments: { query: 'ultra-frontend' } });
    const findExactText = findExact.result?.content?.[0]?.text || '';
    console.log(`\n4. find_skills("ultra-frontend") — exact match`);
    console.log(`   Response size: ${findExactText.length} chars`);
    console.log(`   Est. tokens: ~${estimateTokens(findExactText)}`);

    // 5. find_skills fuzzy
    const findFuzzy = await rpc(proc, 'tools/call', { name: 'find_skills', arguments: { query: 'data' } });
    const findFuzzyText = findFuzzy.result?.content?.[0]?.text || '';
    console.log(`\n5. find_skills("data") — fuzzy`);
    console.log(`   Response size: ${findFuzzyText.length} chars`);
    console.log(`   Est. tokens: ~${estimateTokens(findFuzzyText)}`);

    // 6. apply_skill compact
    const applyCompact = await rpc(proc, 'tools/call', { name: 'apply_skill', arguments: { skillName: 'ultra-frontend', input: 'Build a dashboard' } });
    const applyCompactText = applyCompact.result?.content?.[0]?.text || '';
    console.log(`\n6. apply_skill("ultra-frontend") — compact`);
    console.log(`   Response size: ${applyCompactText.length} chars`);
    console.log(`   Est. tokens: ~${estimateTokens(applyCompactText)}`);

    // 7. auto_skill_match
    const autoMatch = await rpc(proc, 'tools/call', { name: 'auto_skill_match', arguments: { taskDescription: 'I need to style a web page with CSS animations' } });
    const autoMatchText = autoMatch.result?.content?.[0]?.text || '';
    console.log(`\n7. auto_skill_match("style a web page")`);
    console.log(`   Response size: ${autoMatchText.length} chars`);
    console.log(`   Est. tokens: ~${estimateTokens(autoMatchText)}`);

    // 8. skill_stats
    const stats = await rpc(proc, 'tools/call', { name: 'skill_stats', arguments: {} });
    const statsText = stats.result?.content?.[0]?.text || '';
    console.log(`\n8. skill_stats`);
    console.log(`   Response size: ${statsText.length} chars`);
    console.log(`   Est. tokens: ~${estimateTokens(statsText)}`);

    // Summary
    console.log(`\n=== SUMMARY ===`);
    console.log(`Tool schemas (always in context):  ~${estimateTokens(toolsJson)} tokens`);
    console.log(`list_skills compact:               ~${estimateTokens(listCompactText)} tokens`);
    console.log(`list_skills verbose:               ~${estimateTokens(listVerboseText)} tokens`);
    console.log(`Typical startup burn (schemas only): ~${estimateTokens(toolsJson)} tokens`);
    console.log(`If Claude auto-calls list_skills:    +~${estimateTokens(listCompactText)} tokens`);
    console.log(`Total typical startup:              ~${estimateTokens(toolsJson) + estimateTokens(listCompactText)} tokens`);

  } finally {
    proc.kill();
  }
}

main().catch(e => { console.error(e); process.exit(1); });
