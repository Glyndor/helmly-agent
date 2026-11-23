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

The job that signs and publishes runs in the `release` environment, whose
deployment policy accepts `main` and `v*` tags only, and the signing key is a
secret of that environment. A manual run from any other branch can rehearse a
release (`dry_run`) but never reaches the key.

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
through the `test-command` of `reusable-shell-ci.yml`, naming the runner and
not one file, so a new `tests/*.test.sh` is picked up by existing rather
than by remembering to edit a workflow input. The README covers
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
cargo audit --deny warnings
cargo deny check
python3 .github/scripts/ci/structure.py --exceptions .github/structure.json
```
The Rust toolchain is the one `rust-toolchain.toml` names. `cargo audit` and
`cargo deny` are the release binaries pinned in
`.github/actions/cargo-audit/action.yml`, with the ignores in
`.cargo/audit.toml` and `deny.toml`.
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
worst place to find out a script is broken. `setup-agent.sh` has 944 code
lines, the one file over the 500-line limit; `.github/structure.json` lists it
with a ceiling that can only go down (#153).

## Workflows

CI is split by responsibility rather than gathered in one file:

| file | what runs there |
|---|---|
| `ci.yml` | on a pull request into `develop` or `main`, and on a push to `develop`: the plan (`decide`), DCO, workflow lint, the shell suite, the Rust suite (rustfmt and clippy, then the tests once, run under coverage), the dependency audit, the structure check, the pins check, and `ci-gate`, the check a pull request must pass (see below) |
| `codeql.yml` | CodeQL analysis of the workflows and the Rust code, on pull requests and pushes to `develop` and `main`, and weekly |
| `wiring-guard.yml` | on a pull request into `develop` or `main`: the wiring validator of the base commit runs on the `.github` of the change, which is written into a directory as files and never run (see below) |
| `audit.yml` | the weekly `cargo audit` of the lockfile of `main` and of `develop`, taken out of git as data, for advisories published while nothing is pushed (`cargo deny` runs in the `audit` job of `ci.yml`) |
| `freshness.yml` | weekly: fails when Dependabot has gone quiet |
| `dependabot-security-watch.yml` | lists Dependabot security pull requests stuck against `main` |
| `main-guard.yml` | a pull request into `main` whose head is not `develop` |
| `release.yml` | tag-driven release, signing, attestation, pinned-key parity |

Every reusable this repository calls lives in `.github/workflows/reusable-*.yml`.
They are this repository's own files; nothing is pulled from another one.

**A suite runs only when its paths changed.** `.github/ci-map.json` names the
suites (`rust`, `shell`, `workflows`), the paths that rerun
all of them and the paths no suite looks at. The `decide` job reads the changed
paths against it, using the script and the map of the base commit. A file the map
does not know runs everything, and `tests/ci-map.test.sh` fails for a tracked file
that no suite claims. Add the path of a new file to the map in the same change.

**What a pull request must pass.** GitHub counts a skipped required check as
passed, so no suite is required by its own name. `ci-gate` always runs and fails
unless the plan succeeded and each suite succeeded or was skipped because the
plan said it had nothing to check; the audit, the structure check and the pins check have no plan and
must succeed. The gate is named by the base branch: `ci-gate` for a pull request
into `develop`, `ci-gate (main)` for one into `main` (which runs every suite with no
plan), and `ci-gate (push)` for a push, so the result of one event cannot satisfy the
requirement of another. The rulesets require `ci-gate` and the DCO check on
`develop`, and `ci-gate (main)` and `develop-only` on `main`, together with the
CodeQL rule.
`.github/required-checks.json` is a copy of those names, and
`tests/ci-wiring.test.sh` fails when a workflow stops emitting one.

**Wiring guard.** The wiring tests run from the tree of the pull request, so a
change that edits a workflow and the test that guards it would validate itself.
`wiring-guard.yml` runs on `pull_request_target`, which GitHub reads from the base
branch, with a read-only token and no secret. It checks out the base, writes the
`.github` of the change (`refs/pull/<n>/merge`, after checking that its second parent is
the head of the event, since GitHub makes that ref in the background) into
a directory with `tests/lib/ci_wiring_extract.py`, which refuses links, submodules and
oversized files, and runs `python3 -I tests/lib/ci_wiring.py` of the base on it. Nothing
of the change is run, imported or sourced, and the tables of the contract are the
base's. A change to an invariant is therefore a pull request of its own, merged before
the change that needs it.

**Pins.** The wiring tests do not compare the value of a pin, so that the pull
requests of Dependabot, which change a SHA and its version comment together, pass.
`.github/scripts/ci/pins.py` judges the value instead, on every pull request and
push: each `uses` is from `actions` or `github`, is pinned to a SHA with a
`# vMAJOR.MINOR.PATCH` comment, and that SHA is the commit the tag of that version
points at in that repository (asked with `git ls-remote`; if the question cannot be
answered the check fails). One repository has one pin in the whole tree, and a
pull request cannot lower the version the base has. On a pull request the script
of the base commit runs first. Images must be pinned by digest and come from a list
that is empty today.

**The cheap checks come first.** The workflow lint, the shell suite and the DCO
check gate the Rust suite on a pull request; inside it the tests are built and
run once, after lint, under coverage. The dependency audit has no plan and is not
behind any gate, and nothing is cancelled across workflows: CodeQL, the audit and
DCO are never left unrun by a functional failure. A newer run of the same pull
request cancels the older one of `ci.yml` and of CodeQL, which has to be repeated
anyway; a push to `develop` or `main` and the weekly runs are grouped by commit or
by run and are never cancelled.

**Job ids are load-bearing.** A required status check is named by its job, and
for a reusable by `<caller job id> / <inner job name>`, so renaming a job renames
its check and creates a phantom the ruleset still requires, which blocks every
pull request with no explanation. Move jobs between files freely; renaming one is
a ruleset change.

## Security

Never open a public issue for a vulnerability. Use the Security tab →
**Report a vulnerability**. The organisation's `SECURITY.md` applies
here and is deliberately not duplicated in this repository.
