#!/usr/bin/env bash
#
# Tests that release.yml still says what the signing of a release relies on: the tag is
# resolved once, only one job reads the release key, the artifacts are data, the build
# holds no authority over the release, and a rehearsal publishes nothing. The checks are
# in tests/lib/ci_wiring_release.py; each case below breaks one of them in a copy of the
# workflow and asserts which finding comes back.

# shellcheck disable=SC2016,SC1091,SC2154 # the text sabotaged below is literal workflow text, `${{ ... }}` included; the helpers are sourced from lib/ (linted there as its own file) and set `fail`
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

source "$(dirname "${BASH_SOURCE[0]}")/lib/wiring.sh"

# --- the release workflow --------------------------------------------------------------
release_case() { # release_case <description> <expected> <old> <new> [count]
	fresh_copy
	[[ -z "${BUMPED:-}" ]] || bump_pins
	python3 - "$WORK/tree/.github/workflows/release.yml" "$3" "$4" "${5:-1}" << 'PY'
import re, sys
path, old, new, count = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
text = open(path).read()
# A pin in the text to find is any pin of that action, so that a bump of its SHA and
# version, which Dependabot makes, does not make the case look for text that is gone.
pin = re.compile(r"((?:actions|github)/[\w./-]+)@[0-9a-f]{40}(?: # v[0-9.]+)?")
pattern = ""
last = 0
for m in pin.finditer(old):
	pattern += re.escape(old[last:m.start()]) + re.escape(m.group(1)) + r"@[0-9a-f]{40}(?: # v[0-9.]+)?"
	last = m.end()
pattern += re.escape(old[last:])
if not re.search(pattern, text):
	sys.exit("sabotage target not found: " + old)
open(path, "w").write(re.sub(pattern, lambda _: new, text, count=count))
PY
	caught "$1" "$2"
}
release_case "a cache in the build job is caught" "uses a cache; a release is built from nothing but the commit" \
	'      - name: Install musl toolchain (x86_64)' '      - uses: actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9
        with:
          path: target
          key: x

      - name: Install musl toolchain (x86_64)'
release_case "a checkout of the tag by name is caught" "checks out a ref; every job runs at the commit of the run" \
	'      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: Validate tag format' '      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          ref: ${{ inputs.tag }}
          persist-credentials: false

      - name: Validate tag format'
release_case "a tag shape that accepts anything is caught" "the step with id \`tag\` must check the tag against" \
	'^v[0-9]+\.[0-9]+\.[0-9]+$' '^v'
release_case "a job that reads the tag from the event is caught" "reads the tag from the event; it takes it from needs.verify.outputs.tag" \
	'          TAG: ${{ needs.verify.outputs.tag }}
          RUN_SHA' '          TAG: ${{ github.ref_name }}
          RUN_SHA'
release_case "a release that does not depend on verify is caught" "does not depend on verify" \
	'  release:
    name: Publish release
    needs: [verify, build, attest]' '  release:
    name: Publish release
    needs: []'
release_case "a release without its dry-run condition is caught" "release must run only when dry_run is not set" \
	'    if: ${{ !inputs.dry_run }}
    runs-on: ubuntu-latest
    timeout-minutes: 20' '    runs-on: ubuntu-latest
    timeout-minutes: 20'
release_case "the release key read by the rehearsal is caught" "reads a secret; only release signs with the release key" \
	'      - name: Make a throwaway key' '      - name: Not a throwaway key
        env:
          K: ${{ secrets.GLYNDOR_RELEASE_ED25519_KEY }}
        run: echo "$K" > /dev/null

      - name: Make a throwaway key'
release_case "a write token in the build job is caught" "can write to the repository; only release publishes" \
	'    permissions:
      contents: read

    strategy:' '    permissions:
      contents: write

    strategy:'
release_case "artifacts downloaded merged into one folder are caught" "must download exactly the two named artifacts" \
	'          path: ${{ runner.temp }}/artifacts/x86_64' '          path: ${{ runner.temp }}/artifacts/x86_64
          merge-multiple: true' 2
release_case "artifacts downloaded into the checkout are caught" "must download exactly the two named artifacts" \
	'          path: ${{ runner.temp }}/artifacts/arm64' '          path: dist/arm64' 2
release_case "a signer called straight from the workflow is caught" "must sign by running the signing script on the three directories and nothing else" \
	'        run: bash "$GITHUB_WORKSPACE/.github/scripts/release/sign-artifacts.sh" "$RUNNER_TEMP/artifacts" "$RUNNER_TEMP/installers" "$RUNNER_TEMP/release"' '        run: python3 "$GITHUB_WORKSPACE/.github/scripts/sign.py" "$RUNNER_TEMP/artifacts/x86_64/helmly-agent-linux-x86_64"' 2
release_case "a Python started without -I is caught" "runs Python without -I" \
	'          for f in helmly-agent-linux-x86_64 helmly-agent-linux-arm64 setup-agent.sh update-agent.sh SHA256SUMS; do
            "$RUNNER_TEMP/signvenv/bin/python" -I "$GITHUB_WORKSPACE/.github/scripts/verify-release.py" "$f" "$THROWAWAY_PUBLIC_KEY"' '          for f in helmly-agent-linux-x86_64 helmly-agent-linux-arm64 setup-agent.sh update-agent.sh SHA256SUMS; do
            "$RUNNER_TEMP/signvenv/bin/python" "$GITHUB_WORKSPACE/.github/scripts/verify-release.py" "$f" "$THROWAWAY_PUBLIC_KEY"'
release_case "a library installed without hashes is caught" "installs a library without hashes on one line" \
	'-m pip install --quiet --require-hashes --only-binary=:all: -r' '-m pip install --quiet -r' 2
release_case "a build job with the identity to attest is caught" "holds id-token: write; only attest, which compiles nothing, does" \
	'    permissions:
      contents: read

    strategy:' '    permissions:
      contents: read
      id-token: write

    strategy:'
release_case "a build job with more than read access is caught" "build compiles and installs tools, so it holds only contents: read" \
	'    permissions:
      contents: read

    strategy:' '    permissions:
      contents: read
      packages: write

    strategy:'
release_case "an attestation that runs in a rehearsal is caught" "attest must not run in a rehearsal" \
	'    name: Attest the provenance of the binaries
    needs: [verify, build]
    if: ${{ !inputs.dry_run }}' '    name: Attest the provenance of the binaries
    needs: [verify, build]'
release_case "an attest job that checks out code is caught" "attest must only download, check and attest" \
	'    steps:
      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2
        with:
          name: agent-x86_64
          path: ${{ runner.temp }}/artifacts/x86_64

      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2
        with:
          name: agent-arm64
          path: ${{ runner.temp }}/artifacts/arm64

      - name: Require exactly the two binaries' '    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2
        with:
          name: agent-x86_64
          path: ${{ runner.temp }}/artifacts/x86_64

      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2
        with:
          name: agent-arm64
          path: ${{ runner.temp }}/artifacts/arm64

      - name: Require exactly the two binaries'
release_case "the identity to attest given to the release job is caught" "holds id-token: write; only attest, which compiles nothing, does" \
	'    environment: release
    permissions:
      contents: write' '    environment: release
    permissions:
      contents: write
      id-token: write'
release_case "a rehearsal with permissions of its own is caught" "the rehearsal must get no permissions of its own" \
	'    if: ${{ inputs.dry_run }}
    runs-on: ubuntu-latest
    timeout-minutes: 15' '    if: ${{ inputs.dry_run }}
    runs-on: ubuntu-latest
    timeout-minutes: 15
    permissions:
      contents: read'
release_case "a verify that no longer emits the commit is caught" "verify must output the commit the tag resolved to" \
	'      sha: ${{ inputs.dry_run && github.sha || steps.commit.outputs.sha }}
' ''
release_case "a commit that falls back to the run's own when the tag gave nothing is caught" "fall back to the run's commit for a rehearsal only" \
	'sha: ${{ inputs.dry_run && github.sha || steps.commit.outputs.sha }}' 'sha: ${{ steps.commit.outputs.sha || github.sha }}'
C="the step with id \`commit\` must assign the output of resolve-tag.sh first"
release_case "a verify that resolves the tag without the script is caught" "$C" \
	'sha="$(bash .github/scripts/release/resolve-tag.sh "$TAG" "$RUN_SHA")"' 'sha="$RUN_SHA"'
release_case "a command substitution inside echo, which hides the exit status, is caught" "$C" \
	'          sha="$(bash .github/scripts/release/resolve-tag.sh "$TAG" "$RUN_SHA")"' '          sha=x
          echo "sha=$(bash .github/scripts/release/resolve-tag.sh "$TAG" "$RUN_SHA")" >> "$GITHUB_OUTPUT"'
release_case "a resolved commit that is not checked for its shape is caught" "$C" \
	'          [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "::error::the tag did not resolve to a commit"; exit 1; }
' ''
release_case "a release job that no longer refuses an empty verified commit is caught" "the release job must refuse a verified commit that is not 40 hex digits" \
	'          [[ "$VERIFIED_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "::error::verify did not hand over a commit"; exit 1; }
' ''
release_case "a release created without --verify-tag is caught" "the release is created with --verify-tag and without --target" \
	'gh release create "$TAG" --verify-tag --generate-notes' 'gh release create "$TAG" --generate-notes'
release_case "a release created with --target is caught" "the release is created with --verify-tag and without --target" \
	'gh release create "$TAG" --verify-tag --generate-notes' 'gh release create "$TAG" --verify-tag --target main --generate-notes'
release_case "a release that does not check the tag again before it publishes is caught" "the tag must be checked again right before the release is created" \
	'      - name: The tag still points at the commit that was verified' '      - name: Not the check'
release_case "a release that no longer checks the run commit against the verified one is caught" "release must check that the run is at the commit verify resolved" \
	'[ "$RUN_SHA" = "$VERIFIED_SHA" ]' 'true'
release_case "a release that does not wait for the attestation is caught" "release must wait for the attestation" \
	'    needs: [verify, build, attest]' '    needs: [verify, build]'
release_case "a cross installed without a version is caught" "cross must be installed at a pinned version" \
	'cargo install cross --locked --version 0.2.5' 'cargo install cross --locked'

# --- the environment that holds the key -------------------------------------------------
release_case "a signing job without the environment is caught" "the job that signs must declare \`environment: release\`, exactly" \
	'    environment: release
' ''
release_case "a signing job in another environment is caught" "the job that signs must declare \`environment: release\`, exactly" \
	'    environment: release' '    environment: publish'
release_case "the secret named in a job with no environment is caught" "names a secret and declares no environment" \
	'  attest:
    name: Attest' '  attest:
    env:
      LEAK: ${{ secrets.GLYNDOR_RELEASE_ED25519_KEY }}
    name: Attest'
release_case "the environment moved to a rehearsal is caught" "declares an environment; only the signing job does" \
	'  sign-dry-run:' '  sign-dry-run:
    environment: release'
release_case "the key read by a second job with its own environment is caught" "reads the key and is not the signing job" \
	'  attest:
    name: Attest' '  attest:
    environment: release
    env:
      LEAK: ${{ secrets.GLYNDOR_RELEASE_ED25519_KEY }}
    name: Attest'
release_case "a signing job whose first step is a checkout is caught" "the first step of the signing job must be the secretless check" \
	'      - name: This run was started by a tag, or by hand from main or a tag' '      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: This run was started by a tag, or by hand from main or a tag'
release_case "a guard that lets any branch through is caught" "the first step of the signing job must be the secretless check" \
	'workflow_dispatch:refs/heads/main) ;;' 'workflow_dispatch:refs/heads/*) ;;'

# The commit step of verify, run against a resolve-tag.sh that fails, says nothing, or lies.
python3 -I - "$ROOT/.github/workflows/release.yml" "$WORK/commit.sh" << 'PY'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
step = [s for s in doc["jobs"]["verify"]["steps"] if s.get("id") == "commit"][0]
open(sys.argv[2], "w").write(step["run"])
PY
GOOD=0123456789abcdef0123456789abcdef01234567
# commit_step <resolve-tag.sh body>: exit code, and what the step wrote to GITHUB_OUTPUT
commit_step() {
	local rc=0
	rm -rf "${WORK:?}/c" && mkdir -p "$WORK/c/.github/scripts/release"
	printf '%s\n' "$1" > "$WORK/c/.github/scripts/release/resolve-tag.sh"
	: > "$WORK/c/out"
	(cd "$WORK/c" && env TAG=v2.0.2 RUN_SHA=$GOOD GITHUB_OUTPUT="$WORK/c/out" bash "$WORK/commit.sh" > /dev/null 2>&1) || rc=$?
	echo "$rc:$(cat "$WORK/c/out")"
}
check "a tag that resolves hands its commit on" "0:sha=$GOOD" "$(commit_step "echo $GOOD")"
check "a script that fails and prints nothing fails the step and writes nothing" "1:" "$(commit_step 'exit 1')"
check "a script that fails after printing a commit fails the step and writes nothing" "1:" "$(commit_step "echo $GOOD; exit 1")"
check "a script that succeeds and prints nothing fails the step" "1:" "$(commit_step 'exit 0')"
check "a script that prints something that is not a commit fails the step" "1:" "$(commit_step 'echo main')"
check "a script that prints an abbreviated commit fails the step" "1:" "$(commit_step 'echo 0123456')"
check "a script that prints an upper case commit fails the step" "1:" "$(commit_step 'echo 0123456789ABCDEF0123456789ABCDEF01234567')"

# The guard step itself, run with the events and refs it must tell apart.
python3 -I - "$ROOT/.github/workflows/release.yml" "$WORK/guard.sh" << 'PY'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
open(sys.argv[2], "w").write(doc["jobs"]["release"]["steps"][0]["run"])
PY
guard() { # guard <event> <ref>
	local rc=0
	env EVENT="$1" REF="$2" bash "$WORK/guard.sh" > /dev/null 2>&1 || rc=$?
	echo "$rc"
}
check "a pushed tag starts a release" "0" "$(guard push refs/tags/v2.0.2)"
check "a dispatch from a tag starts a release" "0" "$(guard workflow_dispatch refs/tags/v2.0.2)"
check "a dispatch from main starts a release" "0" "$(guard workflow_dispatch refs/heads/main)"
check "a dispatch from develop is refused" "1" "$(guard workflow_dispatch refs/heads/develop)"
check "a dispatch from a branch named like a version is refused" "1" "$(guard workflow_dispatch refs/heads/v2.0.2)"
check "a pushed branch is refused" "1" "$(guard push refs/heads/main)"
check "a pull request is refused" "1" "$(guard pull_request refs/pull/1/merge)"
check "a ref that only starts like main is refused" "1" "$(guard workflow_dispatch refs/heads/main-evil)"
check "an empty event is refused" "1" "$(guard '' refs/tags/v2.0.2)"

# The same cases on a tree whose pins were all bumped: none of them depends on the value of a pin.
if [[ -z "${BUMPED:-}" ]]; then
	rc=0
	BUMPED=1 bash "${BASH_SOURCE[0]}" > "$WORK/bumped.out" 2>&1 || rc=$?
	check "the release cases give the same answers on a tree whose pins were bumped" "0" "$rc"
	grep -v '^ok' "$WORK/bumped.out" | head -n 5 || true
fi

exit "$fail"
