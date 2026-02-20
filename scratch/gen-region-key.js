#!/usr/bin/env node
// Generate MeshCore region key for a given string.
// Key = first 16 bytes of SHA256(regionName). Usage: node scratch/gen-region-key.js "<region name>"

const { calcRegionKey, bytesToHex } = require('../dist/index.js');

const name = process.argv[2];
if (name === undefined || name === '-h' || name === '--help') {
  console.error('Usage: node scratch/gen-region-key.js "<region name>"');
  console.error('Example: node scratch/gen-region-key.js "#Europe"');
  process.exit(name === undefined ? 1 : 0);
}

const key = calcRegionKey(name);
console.log(bytesToHex(key));
