// Which executable the extension runs (inventory defect 16).
//
// A workspace must not be able to choose it: a cloned repository's .vscode/settings.json could
// otherwise point cloudPosture.binaryPath at a script in the repo and get it executed on open.
// Rules:
//   * only the user-level (global) value of cloudPosture.binaryPath counts; workspace and
//     workspace-folder values are ignored (and the setting is "machine"-scoped in package.json,
//     so VS Code itself refuses it in workspace settings);
//   * the default ("cloud-posture", resolved on PATH) needs no prompt;
//   * any other path runs only after an explicit modal trust prompt for that exact path, whose
//     answer is remembered in the extension's global state.
// Kept free of the vscode module so it can be unit-tested with node --test.
const DEFAULT_BINARY = 'cloud-posture';
const TRUST_KEY = 'cloudPosture.trustedBinary';

async function resolveBinary({ config, state, prompt, warn }) {
  const info = config.inspect('binaryPath') || {};
  const ws = info.workspaceFolderValue !== undefined ? info.workspaceFolderValue : info.workspaceValue;
  if (ws !== undefined && ws !== info.globalValue && warn) {
    warn('cloud-posture: the workspace setting cloudPosture.binaryPath is ignored; set it in your user settings instead.');
  }
  const bin = (typeof info.globalValue === 'string' && info.globalValue.trim()) || info.defaultValue || DEFAULT_BINARY;
  if (bin === DEFAULT_BINARY) return bin;
  if (state.get(TRUST_KEY) === bin) return bin;
  const ok = await prompt(bin);
  if (!ok) return null;
  await state.update(TRUST_KEY, bin);
  return bin;
}

module.exports = { resolveBinary, DEFAULT_BINARY, TRUST_KEY };
