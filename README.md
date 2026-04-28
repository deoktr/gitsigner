# gitsigner

Audit a git repository to ensure every commits are signed by an identity authorized in an `allowed_signers` formatted file. A small, fast, single-binary CLI for use in CI gates, pre-push hooks, and on-demand audits.

## Install

`gitsigner` is distributed as a single binary. There is no runtime to install. There is one prerequisite on the target machine: a working `git` binary on `PATH`, with SSH-signing support (`git` ≥ 2.34), that's the same `git` your developers are already using to sign commits.

Each release ships archives + SHA-256 checksums for the targets below. Pick the matching one from the [releases page](https://github.com/deoktr/gitsigner/releases/latest):

<details>
<summary>Linux</summary>

Linux x86_64:

```bash
curl -fsSL -O https://github.com/deoktr/gitsigner/releases/latest/download/gitsigner-x86_64-unknown-linux-gnu.tar.gz
curl -fsSL -O https://github.com/deoktr/gitsigner/releases/latest/download/gitsigner-x86_64-unknown-linux-gnu.sha256
sha256sum -c gitsigner-x86_64-unknown-linux-gnu.sha256
tar -xzf gitsigner-x86_64-unknown-linux-gnu.tar.gz
sudo install -m 0755 gitsigner /usr/local/bin/gitsigner
gitsigner --version
rm gitsigner gitsigner-x86_64-unknown-linux-gnu.sha256 gitsigner-x86_64-unknown-linux-gnu.tar.gz
```

Linux aarch64:

```bash
curl -fsSL -O https://github.com/deoktr/gitsigner/releases/latest/download/gitsigner-aarch64-unknown-linux-gnu.tar.gz
curl -fsSL -O https://github.com/deoktr/gitsigner/releases/latest/download/gitsigner-aarch64-unknown-linux-gnu.sha256
sha256sum -c gitsigner-aarch64-unknown-linux-gnu.sha256
tar -xzf gitsigner-aarch64-unknown-linux-gnu.tar.gz
sudo install -m 0755 gitsigner /usr/local/bin/gitsigner
gitsigner --version
rm gitsigner gitsigner-aarch64-unknown-linux-gnu.sha256 gitsigner-aarch64-unknown-linux-gnu.tar.gz
```

</details>

<details>
<summary>macOS</summary>

macOS Apple Silicon (aarch64):

```bash
curl -fsSL -O https://github.com/deoktr/gitsigner/releases/latest/download/gitsigner-aarch64-apple-darwin.tar.gz
curl -fsSL -O https://github.com/deoktr/gitsigner/releases/latest/download/gitsigner-aarch64-apple-darwin.sha256
shasum -a 256 -c gitsigner-aarch64-apple-darwin.sha256
tar -xzf gitsigner-aarch64-apple-darwin.tar.gz
sudo install -m 0755 gitsigner /usr/local/bin/gitsigner
gitsigner --version
rm gitsigner gitsigner-aarch64-apple-darwin.sha256 gitsigner-aarch64-apple-darwin.tar.gz
```

macOS Intel (x86_64):

```bash
curl -fsSL -O https://github.com/deoktr/gitsigner/releases/latest/download/gitsigner-x86_64-apple-darwin.tar.gz
curl -fsSL -O https://github.com/deoktr/gitsigner/releases/latest/download/gitsigner-x86_64-apple-darwin.sha256
shasum -a 256 -c gitsigner-x86_64-apple-darwin.sha256
tar -xzf gitsigner-x86_64-apple-darwin.tar.gz
sudo install -m 0755 gitsigner /usr/local/bin/gitsigner
gitsigner --version
rm gitsigner gitsigner-x86_64-apple-darwin.sha256 gitsigner-x86_64-apple-darwin.tar.gz
```

</details>

<details>
<summary>Windows</summary>

Windows (PowerShell):

```powershell
$Url = "https://github.com/deoktr/gitsigner/releases/latest/download/gitsigner-x86_64-pc-windows-msvc.zip"
Invoke-WebRequest -Uri $Url -OutFile gitsigner.zip
Expand-Archive gitsigner.zip -DestinationPath .
.\gitsigner.exe --version
```

</details>

<details>
<summary>From source</summary>

```bash
cargo install --git https://github.com/deoktr/gitsigner
```

</details>

<details>
<summary>Verify a release artifact</summary>

Releases are signed keyless via [Sigstore Cosign](https://docs.sigstore.dev/) using GitHub Actions OIDC. Each archive ships with a `.cosign.bundle` file. To verify:

```bash
TAG=v1.0.0
ASSET=gitsigner-x86_64-unknown-linux-gnu.tar.gz
BASE=https://github.com/deoktr/gitsigner/releases/download/$TAG
curl -fsSL -o "$ASSET" "$BASE/$ASSET"
curl -fsSL -o "$ASSET.cosign.bundle" "$BASE/$ASSET.cosign.bundle"

cosign verify-blob \
  --bundle "$ASSET.cosign.bundle" \
  --certificate-identity "https://github.com/deoktr/gitsigner/.github/workflows/release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "$ASSET"
```

A successful verification proves the archive was produced by the release workflow at the named tag in this repository.

</details>

## Usage

### Provide a policy file

`gitsigner` reads the **same `allowed_signers` file format** that git itself reads when you set `gpg.ssh.allowedSignersFile`. If your team already has one for git's own SSH-signature verification, you are done. Point `gitsigner` at it (or set the git config and let `gitsigner` discover it).

A minimal `allowed_signers` file:

```text
alice@example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH...
bob@example.com   ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM...
```

Each line: principal (typically email) followed by the public key. See `man ssh-keygen` (the `ALLOWED SIGNERS` section) for the full format.

### First audit

In the repo root, with the policy file already configured in git:

```bash
gitsigner
```

Audit a tighter scope:

```bash
gitsigner main..HEAD
```

Audit with an explicit policy path (overrides git config):

```bash
gitsigner --allowed-signers /etc/security/allowed_signers
```

Get machine-readable output for a dashboard:

```bash
gitsigner --format sarif > findings.sarif
```

### CI integration (GitHub Actions)

```yaml
# .github/workflows/signed-commits.yml
name: Signed-commits gate
on:
  pull_request:
  push:
    branches: [main]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          # Default checkout is shallow, deepen so gitsigner can see history.
          fetch-depth: 0

      - name: Install gitsigner
        run: |
          BASE=https://github.com/deoktr/gitsigner/releases/latest/download
          curl -fsSL -O "$BASE/gitsigner-x86_64-unknown-linux-gnu.tar.gz"
          curl -fsSL -O "$BASE/gitsigner-x86_64-unknown-linux-gnu.sha256"
          sha256sum -c gitsigner-x86_64-unknown-linux-gnu.sha256
          tar -xzf gitsigner-x86_64-unknown-linux-gnu.tar.gz
          sudo install -m 0755 gitsigner /usr/local/bin/gitsigner

      - name: Verify signatures
        run: |
          gitsigner --allowed-signers ./.config/allowed_signers \
                    --format sarif > findings.sarif
        continue-on-error: true # let the upload step run even on findings

      - name: Upload findings to Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: findings.sarif
        if: always()

      - name: Re-fail the job on policy violations
        run: gitsigner --allowed-signers ./.config/allowed_signers
```

The two `gitsigner` invocations are intentional: the first emits SARIF for the dashboard regardless of result; the second produces the actual exit-code gate. Both runs hit the same git history and are cheap.

For a PR-only gate (faster, just the new commits):

```yaml
- name: Verify signatures on PR commits
  run: gitsigner ${{ github.event.pull_request.base.sha }}..HEAD
```

### Pre-push hook

`.git/hooks/pre-push`:

```bash
#!/usr/bin/env bash
set -euo pipefail

while read -r local_ref local_oid remote_ref remote_oid; do
  if [[ "$local_oid" == 0000000000000000000000000000000000000000 ]]; then
    # Branch deletion. Nothing to verify.
    continue
  fi

  if [[ "$remote_oid" == 0000000000000000000000000000000000000000 ]]; then
    # New branch, no upstream to compare against; audit everything reachable.
    range="$local_oid"
  else
    range="$remote_oid..$local_oid"
  fi

  if ! gitsigner "$range"; then
    echo "Push blocked by gitsigner. Sign your commits with an authorized key." >&2
    exit 1
  fi
done
```

Make it executable: `chmod +x .git/hooks/pre-push`.

For repo-wide adoption, install via [`pre-commit`](https://pre-commit.com/) or [`lefthook`](https://github.com/evilmartians/lefthook) so every developer gets the hook automatically.

### Adopting on a long-lived repository with unsigned history

If your repository pre-dates your signing policy, you have two options:

```bash
# Option A: grandfather everything before commit X (the adoption point).
gitsigner --since <adoption-commit>

# Option B: explicitly exempt a small handful of legacy commits.
gitsigner --exempt 4f1c8a2 --exempt 9b3e7d1
```

Either way, the report (human and SARIF) records that exemptions were applied, so reviewers can see at a glance that the run was not vacuously passing.

## Exit codes

| Code | Meaning                                                                                               |
| ---- | ----------------------------------------------------------------------------------------------------- |
| 0    | Audit completed; every in-scope artifact passed policy                                                |
| 1    | Audit completed; at least one in-scope artifact violated policy                                       |
| 2    | Usage or configuration error (bad flags, missing allowed-signers, not a git repo, unresolvable range) |
| 3    | Unexpected runtime error                                                                              |

`0` and `1` are reserved exclusively for completed audits. CI scripts may safely branch on `[ $? -eq 1 ]` to mean "found violations".

## Troubleshooting

> Exit `2`, "no allowed-signers source"

Neither `--allowed-signers <path>` nor the `gpg.ssh.allowedSignersFile` git config is set, so `gitsigner` has no policy to enforce. Pass the flag explicitly or set the git config (`git config --global gpg.ssh.allowedSignersFile <path>`).

> Exit `2`, "not a git repository"

The path passed to `-C/--repo` (or the current working directory, when no flag is given) is not inside a git repo. Run from the repo root, or pass `-C <path>` pointing at a working tree or bare repo.

> Exit `1`, all failures are `unsigned` on a freshly adopted repo

The repository pre-dates your signing policy and you are auditing the full history. Either grandfather the legacy commits with `--since <adoption-commit>`, or list specific exemptions with repeated `--exempt <sha>`. See *Adopting on a long-lived repository with unsigned history*.

> Exit `1`, failures are `key-principal-mismatch`

The commit's `committer` email does not match the principal bound to that signer's key in `allowed_signers`. The signature itself is valid, the binding is wrong. Either fix the committer's `user.email` git config so it matches the principal in the policy file, or update the policy file to match the email actually being used.

> Stderr warning "shallow clone" in CI

Default `actions/checkout` does a shallow fetch (`fetch-depth: 1`), so most of history is missing and the audit is silently scoped only to what's local. Add `fetch-depth: 0` to the checkout step (or a depth large enough to cover the audit range).

## What `gitsigner` will not do

- It will not fix your signing setup. If a commit is unsigned, `gitsigner` reports it; you re-author or amend the commit.
- It will not contact a network, no key fetches, no public-key servers, no rebuilds of the policy file. If your `allowed_signers` is out of date, that's an operations problem.
- It will not audit GPG-signed or X.509-signed commits in v1. The `allowed_signers` format is SSH-signing-specific. (See the "Assumptions" section of `spec.md`.)

## License

gitsigner is licensed under [MIT](./LICENSE).
