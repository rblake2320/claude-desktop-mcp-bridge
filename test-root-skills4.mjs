import { spawn } from 'child_process';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const serverPath = join(__dirname, 'dist', 'skills-bridge', 'server.js');

let nextId = 1;

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
  console.log('Starting skills-bridge...');
  const proc = spawn(process.execPath, [serverPath], {
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  let stderr = '';
  proc.stderr.on('data', d => { stderr += d.toString(); });

  let passed = 0, failed = 0;

  function check(cond, msg) {
    if (cond) { console.log(`  PASS: ${msg}`); passed++; }
    else { console.log(`  FAIL: ${msg}`); failed++; }
  }

  try {
    await rpc(proc, 'initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'test', version: '1.0' }
    });

    await new Promise(r => setTimeout(r, 6000));

    // TEST 1: list_skills compact — look for "Skills (N)" pattern
    console.log('\nTEST 1: list_skills compact');
    const list = await rpc(proc, 'tools/call', { name: 'list_skills', arguments: {} });
    const listText = list.result?.content?.[0]?.text || '';
    const countMatch = listText.match(/Skills \((\d+)\)/);
    const count = countMatch ? parseInt(countMatch[1]) : 0;
    console.log(`  Count: ${count}`);
    check(count >= 70, `${count} skills loaded (need 70+)`);

    // TEST 2: find canvas-design (SKILL.md only)
    console.log('\nTEST 2: find canvas-design');
    const find1 = await rpc(proc, 'tools/call', { name: 'find_skills', arguments: { query: 'canvas-design' } });
    check(find1.result?.content?.[0]?.text?.includes('canvas-design'), 'canvas-design found');

    // TEST 3: find docx (SKILL.md only)
    console.log('\nTEST 3: find docx');
    const find2 = await rpc(proc, 'tools/call', { name: 'find_skills', arguments: { query: 'docx' } });
    check(find2.result?.content?.[0]?.text?.includes('docx'), 'docx found');

    // TEST 4: find healthcare (SKILL.md only)
    console.log('\nTEST 4: find healthcare');
    const find3 = await rpc(proc, 'tools/call', { name: 'find_skills', arguments: { query: 'healthcare' } });
    check(find3.result?.content?.[0]?.text?.includes('healthcare'), 'healthcare found');

    // TEST 5: find ultra-frontend (legacy)
    console.log('\nTEST 5: find ultra-frontend (legacy)');
    const find4 = await rpc(proc, 'tools/call', { name: 'find_skills', arguments: { query: 'ultra-frontend' } });
    check(find4.result?.content?.[0]?.text?.includes('ultra-frontend'), 'ultra-frontend found');

    // TEST 6: apply canvas-design (SKILL.md skill)
    console.log('\nTEST 6: apply canvas-design');
    const apply = await rpc(proc, 'tools/call', { name: 'apply_skill', arguments: { skillName: 'canvas-design', input: 'Create a poster' } });
    check(apply.result?.content?.[0]?.text?.toLowerCase()?.includes('canvas-design'), 'canvas-design activated');

    // TEST 7: list with category filter (security)
    console.log('\nTEST 7: list security skills');
    const secList = await rpc(proc, 'tools/call', { name: 'list_skills', arguments: { category: 'security' } });
    const secText = secList.result?.content?.[0]?.text || '';
    check(secText.includes('agent-safety-guardrails') || secText.includes('risk'), 'security category has SKILL.md skills');

    console.log(`\n=== ${passed} passed, ${failed} failed ===`);

    // Key init logs
    console.log('\nInit logs:');
    stderr.split('\n')
      .filter(l => l.includes('Registered') || l.includes('initialized') || l.includes('Bridge') || l.includes('skills total'))
      .forEach(l => console.log('  ' + l));

  } finally {
    proc.kill();
  }

  process.exit(failed > 0 ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
