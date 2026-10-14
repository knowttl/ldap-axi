'use strict';

const { existsSync } = require('node:fs');
const { resolve } = require('node:path');
const nativeResolution = require('../../../scripts/native-resolution.cjs');

const packageRoot = resolve(__dirname, '../../..');

function loadBindings() {
  const release = nativeResolution.releaseAddonPath(packageRoot);
  const status = nativeResolution.readInstallStatus(packageRoot);
  if (status) {
    if (status.result !== 'installed') throw new Error(`native installation is unavailable: ${status.detail}`);
    if (!existsSync(release)) throw new Error('installed native addon is missing');
    return require(release);
  }
  if (existsSync(release)) return require(release);

  const { mode, target } = nativeResolution.selection();
  if (!nativeResolution.validModes.has(mode)) throw new Error('invalid native mode');
  if (!target) throw new Error('unsupported native target');
  if (mode === 'off' || mode === 'source') throw new Error('native prebuild fallback is disabled');
  const bundled = nativeResolution.verifyBundledPrebuild(packageRoot, target);
  if (!bundled) throw new Error('verified prebuild not available');
  return require(bundled.path);
}

module.exports = { loadBindings };
