// cloud-posture VS Code extension: runs `cloud-posture scan --iac <folder> --output json` and maps
// findings to Diagnostics (inline squiggles), with Quick Fix code actions that apply the HCL patch
// (`cloud-posture fix --id <id> --patch`) or insert the generated Terraform.
const vscode = require('vscode');
const cp = require('child_process');
const path = require('path');
const fs = require('fs');
const { resolveBinary } = require('./binary');

const IAC_LANGS = new Set(['terraform', 'hcl', 'yaml', 'json', 'bicep', 'dockerfile']);
let diagnostics;
let lastFindings = [];
let extContext;
let warnedWorkspaceBinary = false;

function cfg(key) { return vscode.workspace.getConfiguration('cloudPosture').get(key); }

function sevToVS(sev) {
  switch (sev) {
    case 'CRITICAL': case 'HIGH': return vscode.DiagnosticSeverity.Error;
    case 'MEDIUM': return vscode.DiagnosticSeverity.Warning;
    case 'LOW': return vscode.DiagnosticSeverity.Information;
    default: return vscode.DiagnosticSeverity.Hint;
  }
}

// binary returns the executable to run, or null when the user declined to trust it (defect 16).
function binary() {
  return resolveBinary({
    config: vscode.workspace.getConfiguration('cloudPosture'),
    state: extContext.globalState,
    prompt: async (bin) => {
      const pick = await vscode.window.showWarningMessage(
        `cloud-posture will run the executable ${bin} (from your user settings). Trust and run it?`,
        { modal: true }, 'Trust and run');
      return pick === 'Trust and run';
    },
    warn: (msg) => { if (!warnedWorkspaceBinary) { warnedWorkspaceBinary = true; vscode.window.showWarningMessage(msg); } },
  });
}

async function runCLI(args, cwd) {
  const bin = await binary();
  if (!bin) throw new Error('the configured cloud-posture binary was not trusted; nothing was run');
  return new Promise((resolve, reject) => {
    cp.execFile(bin, args, { cwd, maxBuffer: 64 * 1024 * 1024 }, (err, stdout, stderr) => {
      // scan exits non-zero when findings exceed --fail-on; still parse output
      if (err && !stdout) return reject(new Error(stderr || err.message));
      resolve(stdout);
    });
  });
}

async function scan(root, singleFile) {
  const target = singleFile || root;
  const args = ['scan', '--iac', target, '--output', 'json', '--no-store', '--quiet', ...(cfg('extraArgs') || [])];
  let out;
  try { out = await runCLI(args, root); } catch (e) {
    vscode.window.showErrorMessage(`cloud-posture: ${e.message}. Install: https://github.com/DreadpiratePickles/nimbus`);
    return;
  }
  let data;
  try { data = JSON.parse(out); } catch (e) { vscode.window.showErrorMessage('cloud-posture: could not parse scan output'); return; }
  const findings = (data.findings || data).filter(f => f.status === 'FAIL' && f.file);
  lastFindings = findings;
  const minRank = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 }[cfg('minSeverity') || 'LOW'] || 2;
  const byFile = new Map();
  for (const f of findings) {
    const rank = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 }[f.severity] || 1;
    if (rank < minRank) continue;
    const abs = path.isAbsolute(f.file) ? f.file : path.join(root, f.file);
    const line = Math.max((f.line_start || 1) - 1, 0);
    const endLine = Math.max((f.line_end || f.line_start || 1) - 1, line);
    const range = new vscode.Range(line, 0, endLine, 1000);
    const d = new vscode.Diagnostic(range, `${f.title} [${f.canonical_id}] (${f.source})${f.description ? ' — ' + f.description : ''}`, sevToVS(f.severity));
    d.source = 'cloud-posture';
    d.code = { value: f.canonical_id, target: vscode.Uri.parse('https://github.com/DreadpiratePickles/nimbus/blob/main/docs/checks.md#' + f.canonical_id.toLowerCase()) };
    d.findingId = f.id;
    if (!byFile.has(abs)) byFile.set(abs, []);
    byFile.get(abs).push(d);
  }
  diagnostics.clear();
  for (const [file, ds] of byFile) diagnostics.set(vscode.Uri.file(file), ds);
  const n = findings.length;
  vscode.window.setStatusBarMessage(`cloud-posture: ${n} finding${n === 1 ? '' : 's'}`, 5000);
}

class FixProvider {
  provideCodeActions(document, range, context) {
    const actions = [];
    for (const d of context.diagnostics) {
      if (d.source !== 'cloud-posture' || !d.findingId) continue;
      const f = lastFindings.find(x => x.id === d.findingId);
      if (!f) continue;
      const apply = new vscode.CodeAction(`Fix ${f.canonical_id} in place (cloud-posture)`, vscode.CodeActionKind.QuickFix);
      apply.command = { command: 'cloudPosture.applyPatch', title: 'apply', arguments: [f, document] };
      apply.diagnostics = [d];
      apply.isPreferred = true;
      actions.push(apply);
      const gen = new vscode.CodeAction(`Generate Terraform remediation for ${f.canonical_id}`, vscode.CodeActionKind.QuickFix);
      gen.command = { command: 'cloudPosture.generateFix', title: 'generate', arguments: [f] };
      actions.push(gen);
    }
    return actions;
  }
}

async function applyPatch(f, document) {
  const root = vscode.workspace.getWorkspaceFolder(document.uri)?.uri.fsPath || path.dirname(document.uri.fsPath);
  try {
    const out = await runCLI(['fix', '--id', f.id, '--patch', '--iac', root, '--output', 'json'], root);
    const patch = JSON.parse(out);
    if (!patch || !patch.after) { vscode.window.showWarningMessage('No deterministic patch for this finding; use "Generate Terraform remediation".'); return; }
    if (patch.widens_access) { vscode.window.showErrorMessage('Guardrail: the patch would widen access; refusing to apply.'); return; }
    const edit = new vscode.WorkspaceEdit();
    const full = new vscode.Range(0, 0, document.lineCount, 0);
    edit.replace(document.uri, full, patch.after);
    await vscode.workspace.applyEdit(edit);
    vscode.window.showInformationMessage(`cloud-posture: ${patch.explanation}`);
  } catch (e) { vscode.window.showErrorMessage(`cloud-posture fix: ${e.message}`); }
}

async function generateFix(f) {
  const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || process.cwd();
  try {
    const out = await runCLI(['fix', '--finding', f.canonical_id, '--generate-terraform', '--print'], root);
    const doc = await vscode.workspace.openTextDocument({ language: 'terraform', content: out });
    await vscode.window.showTextDocument(doc, { preview: true, viewColumn: vscode.ViewColumn.Beside });
  } catch (e) { vscode.window.showErrorMessage(`cloud-posture fix: ${e.message}`); }
}

function activate(context) {
  extContext = context;
  diagnostics = vscode.languages.createDiagnosticCollection('cloud-posture');
  context.subscriptions.push(diagnostics);
  const root = () => vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  context.subscriptions.push(
    vscode.commands.registerCommand('cloudPosture.scanWorkspace', () => root() && scan(root())),
    vscode.commands.registerCommand('cloudPosture.scanFile', () => { const ed = vscode.window.activeTextEditor; if (ed && root()) scan(root(), ed.document.uri.fsPath); }),
    vscode.commands.registerCommand('cloudPosture.applyPatch', applyPatch),
    vscode.commands.registerCommand('cloudPosture.generateFix', generateFix),
    vscode.commands.registerCommand('cloudPosture.showAttackPaths', async () => {
      try { const out = await runCLI(['paths', '--format', 'mermaid'], root()); const doc = await vscode.workspace.openTextDocument({ language: 'markdown', content: '```mermaid\n' + out + '\n```' }); vscode.window.showTextDocument(doc); } catch (e) { vscode.window.showErrorMessage(e.message); }
    }),
    vscode.commands.registerCommand('cloudPosture.openDashboard', async () => {
      try { await runCLI(['dashboard', '--out', path.join(root(), '.cloud-posture', 'dashboard.html')], root()); vscode.env.openExternal(vscode.Uri.file(path.join(root(), '.cloud-posture', 'dashboard.html'))); } catch (e) { vscode.window.showErrorMessage(e.message); }
    }),
    vscode.languages.registerCodeActionsProvider([{ language: 'terraform' }, { language: 'hcl' }, { language: 'yaml' }, { language: 'json' }, { language: 'bicep' }], new FixProvider(), { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }),
    vscode.workspace.onDidSaveTextDocument(doc => { if (cfg('scanOnSave') && IAC_LANGS.has(doc.languageId) && root()) scan(root(), doc.uri.fsPath); })
  );
  if (root()) scan(root());
}

function deactivate() {}
module.exports = { activate, deactivate };
