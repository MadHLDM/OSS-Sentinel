#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const seedDir = path.resolve(process.cwd(), 'demo', 'seeds');
if (!fs.existsSync(seedDir)) {
  console.error('Seed directory not found:', seedDir);
  process.exit(1);
}
console.log('Demo seeds present at', seedDir);
console.log('API will auto-load seeds when DEMO=1');

