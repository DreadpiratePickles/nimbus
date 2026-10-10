# Security policy

nimbus (`cloud-posture`) runs with read access to your cloud accounts, so we treat its own supply
chain as part of its attack surface. This file says how to report a problem, what we support, how
releases are signed, and how to check them before you run anything.

## Reporting a vulnerability

**Do not open a public issue.** Use either:

- GitHub private vulnerability reporting: <https://github.com/DreadpiratePickles/nimbus/security/advisories/new>
- Email: `security@<project-domain-TBD>` (placeholder; until a project domain exists, use the GitHub
  form above)

Please include affected version (`cloud-posture version`), a reproduction, and impact. We aim to
acknowledge within 3 working days and to agree a disclosure date with you; the default embargo is
90 days or the release of a fix, whichever comes first. We credit reporters unless asked not to.

## Supported versions

| Version | Supported |
|---|---|
| latest minor release (`0.x` latest) | yes: security fixes |
| older `0.x` minors | no; upgrade |
| `0.1.0-dev` / unreleased builds from source | best effort only |

Before 1.0, only the newest minor line receives fixes.

## How releases are built and signed

Every release is produced by `.github/workflows/release.yml` on a `v*` tag, on GitHub-hosted
runners, with [goreleaser](.goreleaser.yaml). Nothing is built or uploaded from a laptop.

- **Archives** for linux/darwin/windows × amd64/arm64, built with `-trimpath` and `CGO_ENABLED=0`,
  version/commit/date injected by ldflags.
- **`checksums.txt`**: SHA-256 of every archive.
- **Cosign keyless signatures** (Sigstore bundle `*.sigstore.json`) on `checksums.txt` and on every
  archive. The signing certificate identity is
  `https://github.com/DreadpiratePickles/nimbus/.github/workflows/release.yml@refs/tags/<tag>`,
  issuer `https://token.actions.githubusercontent.com`. There is no long-lived signing key to steal.
- **SBOM**: an SPDX JSON SBOM (syft) per archive.
- **SLSA build provenance**: `actions/attest-build-provenance` attests every archive listed in
  `checksums.txt` and the container image.
- **Container image** `ghcr.io/dreadpiratepickles/cloud-posture`: distroless static, non-root
  (uid 65532), multi-arch, BuildKit SBOM + provenance, cosign-signed by digest.
- **Immutable releases** are enabled on the repository: goreleaser uploads into a *draft*, and the
  workflow publishes it only after signing, attestation and a self-verification step pass. Once
  published, assets and the tag cannot be changed. (This is what kept Trivy v0.69.3 safe during the
  2026 tag-rewrite compromise.)
- **All GitHub Actions are pinned by full commit SHA**; Dependabot proposes updates.

## Verifying a release

```sh
TAG=v0.2.0
gh release download "$TAG" --repo DreadpiratePickles/nimbus \
  -p checksums.txt -p checksums.txt.sigstore.json -p "cloud-posture_${TAG#v}_linux_amd64.tar.gz"

# 1. signature on the checksum file (proves it came from this repo's release workflow at this tag)
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/DreadpiratePickles/nimbus/.github/workflows/release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

# 2. the archive matches the signed checksum
sha256sum --ignore-missing -c checksums.txt      # macOS: shasum -a 256 --ignore-missing -c checksums.txt

# 3. SLSA provenance
gh attestation verify "cloud-posture_${TAG#v}_linux_amd64.tar.gz" --repo DreadpiratePickles/nimbus

# container image: pin by digest, and verify it
cosign verify "ghcr.io/dreadpiratepickles/cloud-posture:${TAG#v}" \
  --certificate-identity-regexp '^https://github.com/DreadpiratePickles/nimbus/\.github/workflows/release\.yml@refs/tags/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

`install.sh` performs steps 1 and 2 for you and refuses to install on any mismatch; pass
`--require-signature` to make step 1 mandatory. Never pipe an unpinned script from `main` into a shell.

## Credential rotation policy (all at once)

If any project credential, CI secret, signing path or maintainer account is suspected compromised,
we rotate **every** project credential in one window, not just the one we think leaked. The Trivy
and KICS 2026 incidents showed that partial, sequential rotation lets an attacker who holds one
secret re-steal the others while rotation is in progress.

1. Freeze releases: disable the release workflow and revoke pending tag pushes.
2. In one window, revoke and re-issue: all repository and organisation Actions secrets
   (`HOMEBREW_TAP_GITHUB_TOKEN` and any others), maintainer PATs and SSH/GPG keys, ghcr.io package
   tokens, deploy keys, and any third-party tokens (newsletters, registries).
3. Review audit logs (GitHub org audit log, ghcr.io package versions, the Homebrew tap's history,
   Rekor entries for our signing identity) for activity between the suspected compromise and the
   rotation.
4. Publish an advisory listing affected versions, digests and Rekor log indices; mark bad releases
   and yank bad image tags (the immutable release record remains, flagged in its notes).
5. Re-enable releases only after a fresh tag builds, signs and verifies end to end.

Secrets live only in GitHub Actions secrets / environment protection rules; they are never written
to logs, commits, issues or chat transcripts (only *where* a secret lives is documented).

## Correcting a wrong result

A security tool that reports a false critical, or says a fix closed a path when it did not, causes
harm too. We treat these as correctness incidents, even when they are not vulnerabilities:

- Report them in a public issue, labelled `correctness`. If the details would expose your estate,
  use the private channel above.
- The fix comes with a failing-first test, and a lab or fixture case where one applies
  ([`docs/benchmark.md`](docs/benchmark.md)).
- The release notes name **the rule or path logic** that was wrong, **the fix**, **the affected
  check / rule / path ids**, and **the first release that contains the correction**, so users can tell
  which past results to re-check.
- If the published scoring formula changes, its `score_version` changes too ([`docs/scoring.md`](docs/scoring.md)).

## Scope notes

nimbus reads cloud configuration with the credentials you give it. It does not need write access;
use the read-only roles described in the README ("Credentials" and "Threat model"). Report anything that causes nimbus to write to a
cloud account, leak a credential, or execute code from an untrusted checkout.
