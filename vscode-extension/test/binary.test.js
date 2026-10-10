// Inventory defect 16: a workspace (e.g. a cloned repo's .vscode/settings.json) must not be able
// to choose the executable the extension runs. Only the user-level (global) setting counts, and a
// non-default path runs only after an explicit, remembered trust prompt for that exact path.
// Run: cd vscode-extension && node --test test/
const test = require('node:test');
const assert = require('node:assert');
const { resolveBinary, DEFAULT_BINARY } = require('../src/binary');

function config(values) {
  return { inspect: (key) => (key === 'binaryPath' ? { key: 'cloudPosture.binaryPath', defaultValue: DEFAULT_BINARY, ...values } : undefined) };
}
function state(init = {}) {
  const m = new Map(Object.entries(init));
  return { get: (k) => m.get(k), update: async (k, v) => { m.set(k, v); }, map: m };
}

test('workspace and folder values are ignored', async () => {
  const prompts = [];
  const warned = [];
  const bin = await resolveBinary({
    config: config({ workspaceValue: './evil.sh', workspaceFolderValue: '/tmp/evil' }),
    state: state(), prompt: async (p) => { prompts.push(p); return true; }, warn: (m) => warned.push(m),
  });
  assert.strictEqual(bin, DEFAULT_BINARY);
  assert.deepStrictEqual(prompts, []);
  assert.strictEqual(warned.length, 1);
  assert.match(warned[0], /ignored/);
});

test('user-level path needs an explicit trust prompt, remembered per path', async () => {
  const st = state();
  const prompts = [];
  const opts = { config: config({ globalValue: '/opt/cp/cloud-posture' }), state: st, prompt: async (p) => { prompts.push(p); return true; } };
  assert.strictEqual(await resolveBinary(opts), '/opt/cp/cloud-posture');
  assert.strictEqual(await resolveBinary(opts), '/opt/cp/cloud-posture');
  assert.deepStrictEqual(prompts, ['/opt/cp/cloud-posture']); // asked once
  // a different user-level path asks again
  const opts2 = { ...opts, config: config({ globalValue: '/usr/local/bin/cloud-posture' }) };
  assert.strictEqual(await resolveBinary(opts2), '/usr/local/bin/cloud-posture');
  assert.strictEqual(prompts.length, 2);
});

test('declining the prompt runs nothing', async () => {
  const bin = await resolveBinary({ config: config({ globalValue: '/opt/cp/cloud-posture' }), state: state(), prompt: async () => false });
  assert.strictEqual(bin, null);
});

test('workspace value cannot ride on a trusted user-level value', async () => {
  const st = state({ 'cloudPosture.trustedBinary': '/opt/cp/cloud-posture' });
  const bin = await resolveBinary({ config: config({ globalValue: '/opt/cp/cloud-posture', workspaceValue: '/tmp/evil' }), state: st, prompt: async () => true });
  assert.strictEqual(bin, '/opt/cp/cloud-posture');
});

test('package.json makes binaryPath machine-scoped and restricted in untrusted workspaces', () => {
  const pkg = require('../package.json');
  const prop = pkg.contributes.configuration.properties['cloudPosture.binaryPath'];
  assert.strictEqual(prop.scope, 'machine');
  const caps = pkg.capabilities && pkg.capabilities.untrustedWorkspaces;
  assert.ok(caps && caps.restrictedConfigurations.includes('cloudPosture.binaryPath'));
});
