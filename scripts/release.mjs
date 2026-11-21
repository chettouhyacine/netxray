#!/usr/bin/env node
/**
 * One-command release:
 *
 *   npm run release -- 0.3.0
 *
 * Writes the version to package.json, package-lock.json, public/manifest.json,
 * the HAR creator string and the JSON report version, builds the extension,
 * removes stale netxray-*.zip files and writes netxray-<version>.zip with
 * manifest.json at the archive root.
 *
 * The zip is written by this script (deflate + central directory) so it works
 * the same on Windows, macOS and Linux without extra dependencies.
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateRawSync } from 'node:zlib';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const rel = (...parts) => path.join(root, ...parts);

function fail(message) {
  console.error(`release: ${message}`);
  process.exit(1);
}

const version = (process.argv[2] ?? '').trim();
if (!version) fail('usage: npm run release -- <version>   (for example: npm run release -- 0.3.0)');
if (!/^\d+\.\d+\.\d+$/.test(version)) {
  fail(`"${version}" is not a plain semver version. Expected something like 0.3.0.`);
}

console.log(`release: bumping NetXRay to ${version}`);

function readJson(file) {
  return JSON.parse(fs.readFileSync(rel(file), 'utf8'));
}

function writeJson(file, value) {
  fs.writeFileSync(rel(file), `${JSON.stringify(value, null, 2)}\n`);
}

function replaceOnce(file, pattern, replacement) {
  const target = rel(file);
  const before = fs.readFileSync(target, 'utf8');
  // Test the pattern separately: rerunning with the same version must not fail.
  if (!pattern.test(before)) fail(`could not find the version string in ${file}`);
  fs.writeFileSync(target, before.replace(pattern, replacement));
  console.log(`release: ${file}`);
}

// package.json
const pkg = readJson('package.json');
pkg.version = version;
writeJson('package.json', pkg);
console.log('release: package.json');

// package-lock.json (root version and the "" package entry)
const lock = readJson('package-lock.json');
lock.version = version;
if (!lock.packages?.['']) fail('package-lock.json has no packages[""] entry');
lock.packages[''].version = version;
writeJson('package-lock.json', lock);
console.log('release: package-lock.json');

// public/manifest.json (vite copies it to dist/manifest.json)
const manifest = readJson('public/manifest.json');
manifest.version = version;
writeJson('public/manifest.json', manifest);
console.log('release: public/manifest.json');

// HAR creator string
replaceOnce(
  'src/core/session.ts',
  /(creator: \{ name: 'NetXRay', version: ')[^']+(' \})/,
  `$1${version}$2`,
);

// Exported JSON report version
replaceOnce(
  'src/report/htmlReport.ts',
  /(tool: 'NetXRay',\s*\n\s*version: ')[^']+(')/,
  `$1${version}$2`,
);

// Build
console.log('release: building');
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const build = spawnSync(npm, ['run', 'build'], {
  cwd: root,
  stdio: 'inherit',
  shell: process.platform === 'win32',
});
if (build.status !== 0) fail(`build failed with exit code ${build.status}`);

const dist = rel('dist');
if (!fs.existsSync(dist)) fail('build produced no dist directory');
const built = readJson('dist/manifest.json').version;
if (built !== version) fail(`dist/manifest.json says ${built}, expected ${version}`);

// Zip builder
const crcTable = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let c = i;
    for (let bit = 0; bit < 8; bit += 1) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function dosTimestamp(date) {
  const time =
    ((date.getHours() & 31) << 11) |
    ((date.getMinutes() & 63) << 5) |
    ((Math.floor(date.getSeconds() / 2)) & 31);
  const day =
    (((date.getFullYear() - 1980) & 127) << 9) |
    (((date.getMonth() + 1) & 15) << 5) |
    (date.getDate() & 31);
  return { time, day };
}

function collectEntries(dir, prefix = '') {
  const entries = [];
  const names = fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
  for (const dirent of names) {
    const absolute = path.join(dir, dirent.name);
    const name = `${prefix}${dirent.name}`;
    if (dirent.isDirectory()) {
      entries.push({ name: `${name}/`, data: Buffer.alloc(0), directory: true });
      entries.push(...collectEntries(absolute, `${name}/`));
    } else if (dirent.isFile()) {
      entries.push({ name, data: fs.readFileSync(absolute), directory: false });
    }
  }
  return entries;
}

function buildZip(entries) {
  const now = new Date();
  const stamp = dosTimestamp(now);
  const parts = [];
  const central = [];
  let offset = 0;

  for (const entry of entries) {
    const name = Buffer.from(entry.name, 'utf8');
    const data = entry.data;
    const crc = crc32(data);
    let method = 0;
    let payload = data;
    if (!entry.directory && data.length > 0) {
      const deflated = deflateRawSync(data, { level: 9 });
      if (deflated.length < data.length) {
        method = 8;
        payload = deflated;
      }
    }

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(0x0800, 6); // UTF-8 names
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(stamp.time, 10);
    local.writeUInt16LE(stamp.day, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(payload.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    parts.push(local, name, payload);

    const header = Buffer.alloc(46);
    header.writeUInt32LE(0x02014b50, 0);
    header.writeUInt16LE(20, 4); // version made by
    header.writeUInt16LE(20, 6); // version needed
    header.writeUInt16LE(0x0800, 8);
    header.writeUInt16LE(method, 10);
    header.writeUInt16LE(stamp.time, 12);
    header.writeUInt16LE(stamp.day, 14);
    header.writeUInt32LE(crc, 16);
    header.writeUInt32LE(payload.length, 20);
    header.writeUInt32LE(data.length, 24);
    header.writeUInt16LE(name.length, 28);
    header.writeUInt16LE(0, 30); // extra
    header.writeUInt16LE(0, 32); // comment
    header.writeUInt16LE(0, 34); // disk
    header.writeUInt16LE(0, 36); // internal attrs
    header.writeUInt32LE(entry.directory ? 0x10 : 0, 38); // external attrs
    header.writeUInt32LE(offset, 42);
    central.push(header, name);

    offset += local.length + name.length + payload.length;
  }

  const centralBuffer = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralBuffer.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20);

  return Buffer.concat([...parts, centralBuffer, end]);
}

// Remove zips from earlier versions so there is only one build to hand out.
for (const name of fs.readdirSync(root)) {
  if (/^netxray-.*\.zip$/.test(name) && name !== `netxray-${version}.zip`) {
    fs.unlinkSync(rel(name));
    console.log(`release: removed stale ${name}`);
  }
}

const zipName = `netxray-${version}.zip`;
const entries = collectEntries(dist);
const archive = buildZip(entries);
fs.writeFileSync(rel(zipName), archive);

const files = entries.filter((entry) => !entry.directory).length;
console.log(`release: wrote ${zipName} (${files} files, ${archive.length} bytes)`);
console.log(`release: NetXRay ${version} is ready. Load dist/ unpacked or hand out ${zipName}.`);
