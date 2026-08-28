## Summary

<!-- What does this PR do? 1-3 bullet points. -->

## Changes

<!-- List the main changes made. -->

## Test plan

<!-- How was this tested? Check all that apply. -->

- [ ] `cargo fmt --all --check` is clean
- [ ] `cargo clippy --locked --all-targets --all-features -- -D warnings` is clean
- [ ] `cargo test --locked --all-features --workspace` passes
- [ ] `cargo llvm-cov --locked --workspace --all-features --summary-only --json --output-path coverage.json` meets the ratchet in `ci.yml` (`coverage-threshold`)
- [ ] `shellcheck setup-agent.sh update-agent.sh` is clean
- [ ] `cargo audit --deny warnings --ignore RUSTSEC-2023-0071` and `cargo deny check` pass, for changes to `Cargo.toml`, `Cargo.lock`, `audit.toml` or `deny.toml`

<!--
A test that was not watched fail is not a test. If this PR adds or changes a
check, say which control you removed to make it go red, and what it reported.
Three ways a sabotage lies: it changes nothing, it changes something the
test does not look at, and the red comes from somewhere else entirely.
-->

- [ ] New or changed checks were verified by deleting the control and watching them fail

## Checklist

- [ ] Targets `develop` (release promotion PRs into `main` are merge commits, not squash, and only from `develop`)
- [ ] Commits are signed off (`git commit -s`)
- [ ] Pull request body carries a `Signed-off-by:` trailer (the squash commit GitHub writes is the PR title plus the PR body, and the dco check reads the branch commits)
- [ ] Commits are signed (GPG or SSH, `required_signatures` is enforced)
- [ ] Labels applied (`type:`, `prio:`, `effort:`, `area:` where applicable)
- [ ] No secrets, keys or credentials in code, logs or fixtures
- [ ] Docs updated if behaviour changed

## Related issues

<!-- Closes #123. Does NOT auto-close here: the issue is closed by hand when the fix squashes into develop. -->

Signed-off-by: NAME <EMAIL>
