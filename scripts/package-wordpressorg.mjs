#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const slug = 'boreal-security';
const out = path.join(root, '.wordpressorg-dist');
const stage = path.join(out, slug);
const zip = path.join(out, `${slug}.zip`);
const allowed = [
  'boreal-security.php', 'readme.txt', 'README.md', 'CHANGELOG.md', 'LICENSE', 'uninstall.php',
  'includes/class-database.php', 'includes/class-scanner.php', 'includes/class-login-guard.php',
  'includes/class-admin.php', 'includes/class-integrations.php'
];
fs.rmSync(out, { recursive: true, force: true });
for (const file of allowed) {
  const dest = path.join(stage, file);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(path.join(root, file), dest);
}
execFileSync('zip', ['-Xqr', zip, slug], { cwd: out });
const entries = execFileSync('unzip', ['-Z1', zip], { encoding: 'utf8' }).trim().split('\n').filter(x => x && !x.endsWith('/'));
const expected = allowed.map(x => `${slug}/${x}`).sort();
if (JSON.stringify(entries.sort()) !== JSON.stringify(expected)) throw new Error('ZIP manifest differs from deterministic allowlist.');
const forbidden = [
  [/api\.borealform\.com|\/v1\/licenses\//i, 'licence endpoint'],
  [/\b(?:BSP|Boreal_Security_Pro)_License\b|boreal_security_pro_license/i, 'Pro licence code'],
  [/(?:pre_set|set)_site_transient_update_plugins/, 'commercial updater'],
  [/Plugin Name:\s*Boreal Security Pro/i, 'Pro bootstrap'],
  [/\b(?:entitlement|license_key|licence_key)\b/i, 'entitlement/licence implementation']
];
for (const entry of entries.filter(x => /\.(?:php|js|mjs)$/.test(x))) {
  const source = execFileSync('unzip', ['-p', zip, entry], { encoding: 'utf8' });
  for (const [rule, label] of forbidden) if (rule.test(source)) throw new Error(`${label} leaked into ${entry}`);
}
const main = fs.readFileSync(path.join(root, 'boreal-security.php'), 'utf8');
const readme = fs.readFileSync(path.join(root, 'readme.txt'), 'utf8');
for (const header of ['Plugin Name: Boreal Security', 'Version: 1.0.0', 'Text Domain: boreal-security']) if (!main.includes(header)) throw new Error(`Missing ${header}`);
if (!/Stable tag:\s*1\.0\.0/.test(readme)) throw new Error('Stable tag mismatch.');
const short = readme.split('\n')[10] || '';
if (short.length > 150) throw new Error(`Short description is ${short.length} characters.`);
execFileSync('unzip', ['-tqq', zip], { stdio: 'inherit' });
console.log(`Created ${zip}`);
