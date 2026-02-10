import { readFileSync } from 'fs';
const p = JSON.parse(readFileSync('node_modules/@modelcontextprotocol/sdk/package.json', 'utf8'));
console.log('SDK version:', p.version);

import { readFileSync as rf2 } from 'fs';
const g = JSON.parse(rf2('node_modules/glob/package.json', 'utf8'));
console.log('Glob version:', g.version);

const z = JSON.parse(rf2('node_modules/zod/package.json', 'utf8'));
console.log('Zod version:', z.version);
