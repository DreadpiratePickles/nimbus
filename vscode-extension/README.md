# cloud-posture for VS Code

Inline cloud security for Terraform, CloudFormation, Bicep, Kubernetes and Helm files.

- Findings from `cloud-posture scan --iac` appear as diagnostics (squiggles + Problems panel) at the exact resource block.
- **Quick Fix** → *Fix in place*: applies the deterministic HCL patch (`cloud-posture fix --patch`), guarded so it never widens access.
- **Quick Fix** → *Generate Terraform remediation*: opens the generated fix beside your file.
- Commands: scan workspace, scan file, show attack paths (Mermaid), open dashboard.

Requires the `cloud-posture` binary on your PATH (or set `cloudPosture.binaryPath`). No build step: the extension is plain JavaScript. Package with `npx @vscode/vsce package`.
