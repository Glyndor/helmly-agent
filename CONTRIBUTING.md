# Contributing to helmly-agent

This repository has its own guide because the inherited one describes the
wrong branch flow and the wrong test plan. The shared `CONTRIBUTING.md`
assumes every change targets `develop`, which is true here, but it also
assumes `Closes #N` auto-closes on merge and that `Signed-off-by:` lives on
the commits. Both are incomplete in this repository for reasons that come
from this repository's own shape, not from a global rule. Following the
shared guide lets a pull request land with an unsigned-off squash commit
and a fix that never closes the issue it was meant to close.

This guide is also here because it was missing. The org workflow standard
names four files as inherited from `Glyndor/.github` (code of conduct,
security policy, support, funding), and `CONTRIBUTING.md` is not one of
them. Every repository is supposed to write its own. This one inherited
five: `CONTRIBUTING.md`, the issue templates and the pull request template.
The inheritance is invisible, which is what let it go unnoticed. Nothing
in the tree, in the history, in a clone or in a grep points at it, the
files exist only in GitHub's interface. This file is the first one that
exists in this repository because of it.

Contributions are invitation-only. Bug reports and ideas through issues are
welcome; unsolicited pull requests are not accepted.

## What this repository is

This is the `helmly-agent` daemon. It runs as root on managed Linux VPS
hosts and executes commands sent by the Helmly panel: rootless Podman
containers, nftables firewall rules, WireGuard tunnels and system
maintenance. The release ships a static musl binary for `x86_64` and
`arm64`, signed by an Ed25519 key that is pinned in `setup-agent.sh`,
`update-agent.sh` and the Rust binary itself, and the three pins are
checked against each other on every release.

`release.yml` uploads binaries to GitHub Releases. It does not commit back
to this repository's git. That is why this repository can require pull
requests and status checks, and why release promotion lands by merge commit
rather than squash.

## Branch flow

```
topic branch → PR (squash) → develop → PR (merge commit) → main
```

Branch from `develop`. Open a pull request against `develop` and
squash-merge. Promote to `main` with a `develop → main` release pull
request when a release is ready, merged as a merge commit so the topics
keep their history on `main`. Tags are cut from `main` after the
promotion lands.

`.github/workflows/main-guard.yml` is a hard rule on top of this. A pull
request into `main` whose head branch is not literally `develop` is
refused. A release branch named anything else cannot reach `main`. The
gate exists so code that never went through `develop` cannot be
published.

`Closes #N` does NOT auto-close here. GitHub only auto-closes when a pull
request merges into the default branch, which is `main`, and fixes land
on `develop` first. The issue is closed by hand when the fix squashes
into `develop`. Use `Closes #N` on the pull request body to record
intent, not to drive state.

## Before you open a pull request

- **An issue first.** Labels are the tracking system here, there is no
  board. Apply `type:`, `prio:`, `effort:`, `status:` and `area:` where
  they fit.
- **Sign every commit off** with `git commit -s`. The `dco` check reads
  the commits on the branch, not the squash commit GitHub is about to
  create.
- **The pull request body must also carry a `Signed-off-by:` trailer.**
  GitHub writes the squash commit message as the pull request title plus
  the pull request body, and the dco check reads the branch commits, not
  the squash it is about to build. A body without the trailer lands an
  unsigned-off commit with dco green beside it, and there is no commit
  to repair afterwards.
- **Commits are signed**, GPG or SSH. `required_signatures` is enforced
  on both `develop` and `main`.
- **Conventional Commit title** on the pull request. It becomes the
  squashed commit message.

## Tests

The local surface is `cargo` plus `tests/`. `tests/run.sh` is the shell
suite: it iterates `tests/*.test.sh`, and it fails when it finds none,
so a runner that matches nothing cannot report success. CI calls it
through `reusable-shell-ci.yml`'s `test-command`, naming the runner and
not one file, so a new `tests/*.test.sh` is picked up by existing rather
than by remembering to edit a workflow input. `README.md:29-30` covers
only `cargo build --release` and `cargo test`. Everything beyond that is
what CI runs. Run all of it before pushing:

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features --workspace
cargo llvm-cov --locked --workspace --all-features \
  --summary-only --json --output-path coverage.json
./tests/run.sh
shellcheck -S style setup-agent.sh update-agent.sh tests/*.sh
cargo audit --deny warnings --ignore RUSTSEC-2023-0071
cargo deny check
```
Use **shellcheck v0.11.0**, the version CI pins. This is not pedantry: the
same file is clean under one version and not another. `#170` passed
shellcheck 0.10.0 locally and failed CI, because 0.10.0 reports SC2317
"unreachable" on a stub the sourced code calls and 0.11.0 reports SC2329
"never invoked" on it. So **"shellcheck clean" without naming a version is
not a claim about anything**, and the person most likely to act on it is
the one running a different build.

CI does not merely pin the number. `reusable-shell-ci.yml` pins the
version and the sha256 of that release's tarball together, and its own
input description says they travel as a pair, so overriding one without
the other fails the install. A version pin on its own still trusts
whatever that URL serves today.


Two rules matter more than coverage:

**A test you have not watched fail is not a test.** Before claiming a
check works, delete or invert the control it covers, run it, and confirm
it goes red for the reason it names. The reusable workflow comments
(`reusable-workflow-lint.yml` is the most recent witness) name three
ways a sabotage lies: it changes nothing, it changes something the test
does not look at, and it goes red from somewhere else entirely. All
three have shipped to a green pipeline in this organisation in a single
day.

**Assert which failure fired, never that some failure did.** Every step
in the workflows runs under `set -euo pipefail`, so almost any mistake
exits non-zero and a bare non-zero assertion is satisfied by the failure
you did not mean.

Coverage is ratcheted, not declared. The reusable runs
`cargo llvm-cov --summary-only --json` and gates on the percent it
returns. The threshold lives in `ci.yml` under `coverage-threshold`,
and at the time of writing it is `45`, set honestly
after moving `#[cfg(test)] mod tests` blocks into sibling `tests.rs`
files that cargo-llvm-cov does not count, which dropped measured
coverage from `67.77%` to `47.66%` (the same diff, same commit). Raise
the number in the same pull request that raises coverage, never
silently.

The two installer scripts (`setup-agent.sh`, `update-agent.sh`) are the
only shell in the repository and are linted at shellcheck's strictest
level (`-S style`). Both run as root on a fresh server, which is the
worst place to find out a script is broken. `setup-agent.sh` is around
1,250 lines.

## Workflows

CI is split by responsibility rather than gathered in one file:

| file | what fails there |
|---|---|
| `ci.yml` | rustfmt, clippy, tests, coverage, shellcheck, workflow-lint, Dependabot freshness, audit freshness |
| `audit.yml` | `cargo audit` (RUSTSEC) and `cargo deny`, weekly and on push |
| `dco.yml` | every commit on the pull request carries a `Signed-off-by:` trailer |
| `main-guard.yml` | a pull request into `main` whose head is not `develop` |
| `release.yml` | tag-driven release, signing, attestation, pinned-key parity |

Every reusable this repository calls lives in
`.github/workflows/reusable-*.yml` as a copy taken from a named
`Glyndor/.github` tag. Nothing is pulled remotely.

**Job ids are load-bearing.** A required status check is named
`<caller job id> / <inner job name>`, so renaming a job renames its
check and creates a phantom the ruleset still requires, which blocks
every pull request with no explanation. Move jobs between files freely,
renaming one is a ruleset change.

**The shell CI `test` job is intentionally not enabled.** No shell test
suite exists in this repository, so the reusable's `test` job is passed
no `test-command` and skips on every run. A skipped required check
reports Success, so the `shell / shellcheck` job is the only one of the
two worth promoting to required, and only after it has been seen to
fail.

## Security

Never open a public issue for a vulnerability. Use the Security tab →
**Report a vulnerability**. The organisation's `SECURITY.md` applies
here and is deliberately not duplicated in this repository.
