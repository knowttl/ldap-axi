'use strict';

const { createHash } = require('node:crypto');
const { existsSync, readFileSync } = require('node:fs');
const { join } = require('node:path');

const validModes = new Set(['auto', 'off', 'prebuild', 'source']);
const supportedTargets = new Set(['linux-glibc-x64', 'win32-x64']);

function runtimeReport() {
  try {
    return process.report?.getReport?.();
  } catch {
    return undefined;
  }
}

function isMusl() {
  if (process.platform !== 'linux') return false;
  const report = runtimeReport();
  const sharedObjects = report && Array.isArray(report.sharedObjects) ? report.sharedObjects : [];
  return sharedObjects.some(value => typeof value === 'string' && /(?:^|[/\\])(?:ld-musl-[^/\\]+|libc\.musl-[^/\\]+)(?:\.so(?:\.\d+)*)?$/i.test(value));
}

function targetForRuntime() {
  if (process.platform === 'linux' && process.arch === 'x64' && !isMusl()) return 'linux-glibc-x64';
  if (process.platform === 'win32' && process.arch === 'x64') return 'win32-x64';
  return undefined;
}

function modeForEnvironment() {
  return process.env.LDAP_AXI_NATIVE_MODE ?? 'auto';
}

function selection() {
  return { mode: modeForEnvironment(), target: targetForRuntime() };
}

function readManifest(root) {
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(join(root, 'prebuilds', 'manifest.json'), 'utf8'));
  } catch {
    throw new Error('prebuild manifest is malformed');
  }
  if (manifest?.version !== 1 || typeof manifest.release?.repository !== 'string' || !manifest.artifacts || Array.isArray(manifest.artifacts)) {
    throw new Error('prebuild manifest is malformed');
  }
  return manifest;
}

function validateEntry(entry, target) {
  if (
    entry?.napi !== 9 ||
    entry.patchLevel !== 1 ||
    !/^[a-f0-9]{64}$/.test(entry.sha256) ||
    typeof entry.bundled !== 'boolean' ||
    entry.asset !== `kerberos-${target}.node`
  ) throw new Error('prebuild manifest entry is malformed');
}

function readEntry(root, target) {
  const manifest = readManifest(root);
  const entry = manifest.artifacts[target];
  if (entry !== undefined) validateEntry(entry, target);
  return { manifest, entry };
}

function verifyBundledPrebuild(root, target) {
  if (!supportedTargets.has(target)) throw new Error('unsupported native target');
  const { manifest, entry } = readEntry(root, target);
  if (!entry || !entry.bundled) return undefined;
  const path = join(root, 'prebuilds', target, 'kerberos.node');
  let bytes;
  try {
    bytes = readFileSync(path);
  } catch {
    throw new Error('prebuild artifact missing');
  }
  if (createHash('sha256').update(bytes).digest('hex') !== entry.sha256) throw new Error('prebuild checksum mismatch');
  return { manifest, entry, path, bytes };
}

function releaseAddonPath(root) {
  return join(root, 'build', 'Release', 'kerberos.node');
}

/** Returns the recorded installation outcome, or undefined when native installation never ran. */
function readInstallStatus(root) {
  let text;
  try {
    text = readFileSync(join(root, 'build', 'native-status.json'), 'utf8');
  } catch {
    return undefined;
  }
  let status;
  try {
    status = JSON.parse(text);
  } catch {
    throw new Error('native installation status is malformed');
  }
  if (typeof status?.result !== 'string' || typeof status.detail !== 'string') throw new Error('native installation status is malformed');
  return status;
}

module.exports = {
  existsSync,
  releaseAddonPath,
  readInstallStatus,
  selection,
  targetForRuntime,
  validModes,
  verifyBundledPrebuild,
  readEntry,
};
