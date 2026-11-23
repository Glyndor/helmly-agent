#!/usr/bin/env bash
#
# The version check of update-agent.sh: which release it takes as the latest, when it decides
# there is nothing to do, and what it does when it cannot tell.
#
# The block runs with a `curl` that answers the releases listing from a file and a `uname`
# that answers an architecture, so nothing leaves the machine. A case "proceeds" when the
# block runs to its end, which is where the script goes on to download the binary.

# shellcheck disable=SC2016,SC1091,SC2154 # the fake programs are single-quoted text that runs later; lib/installer.sh is linted as its own file and sets `fail`
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib/installer.sh"

BLOCK="$(block "$UPDATE" '^log_section "Checking versions"' '^# --- Signature verification setup')"

# case_run <name> <installed version, or empty for no file> <FORCE> <releases json> [arch]
case_run() {
	sandbox "$1"
	mkdir -p "$T/etc/glyndor/helmly/bin"
	if [[ -n "$2" ]]; then printf '%s' "$2" > "$T/etc/glyndor/helmly/bin/helmly-agent-version"; fi
	printf '%s' "$4" > "$T/releases.json"
	fake curl 'cat "$T/releases.json"'
	fake uname "echo ${5:-x86_64}"
	run_block "$BLOCK" \
		VERSION_FILE="$T/etc/glyndor/helmly/bin/helmly-agent-version" \
		GITHUB_REPO=Glyndor/helmly-agent FORCE="$3"
}
latest_of() { sed -n 's/.*Latest version: *//p' "$T/out"; }

rel() { # rel <tag> [prerelease] [draft]
	printf '{"tag_name":"%s","prerelease":%s,"draft":%s}' "$1" "${2:-false}" "${3:-false}"
}
LIST="[$(rel v2.0.2),$(rel v2.0.1),$(rel v1.9.0)]"

case_run same 2.0.2 false "$LIST"
check "the installed version equal to the latest does nothing and exits 0" "no:0" "$(reached):$RC"
check "and says so" "1" "$(grep -c 'nothing to do' "$T/out")"

case_run same-forced 2.0.2 true "$LIST"
check "the same version with --force goes on to the download" "yes:0" "$(reached):$RC"

case_run older 2.0.1 false "$LIST"
check "an older installed version goes on to the download" "yes:0" "$(reached):$RC"
check "and names both versions" "1" "$(grep -c 'Updating: 2.0.1 .* 2.0.2' "$T/out")"

case_run no-file '' false "$LIST"
check "with no version file it warns and goes on" "yes:0" "$(reached):$RC"
check "and says the version is unknown" "1" "$(grep -c 'version unknown' "$T/out")"

case_run numeric 2.0.9 false "[$(rel v2.0.9),$(rel v2.0.10),$(rel v2.0.2)]"
check "versions compare as numbers, not as text: 2.0.10 is newer than 2.0.9" "2.0.10" "$(latest_of)"

case_run prerelease 2.0.2 false "[$(rel v9.0.0 true),$(rel v8.0.0 false true),$(rel cli-7.0.0),$(rel v2.0.2)]"
check "a prerelease, a draft and a tag that does not start with v are not the latest" "2.0.2" "$(latest_of)"
check "so an installed latest still has nothing to do" "no:0" "$(reached):$RC"

case_run empty 2.0.2 false '[]'
check "no release at all is a failure" "no:1" "$(reached):$RC"
check "and says that there is none" "1" "$(grep -c 'No agent release found' "$T/out")"

case_run only-drafts 2.0.2 false "[$(rel v3.0.0 false true),$(rel v3.1.0 true)]"
check "only drafts and prereleases is the same failure" "no:1" "$(reached):$RC"

case_run api-down 2.0.2 false '[]'
fake curl 'exit 22'
run_block "$BLOCK" VERSION_FILE="$T/etc/glyndor/helmly/bin/helmly-agent-version" GITHUB_REPO=Glyndor/helmly-agent FORCE=false
check "a releases listing that cannot be fetched stops the update" "no" "$(reached)"
check "with a failure status" "1" "$([[ $RC -ne 0 ]] && echo 1 || echo 0)"

case_run arch 2.0.1 false "$LIST" riscv64
check "an architecture with no release asset is refused" "no:1" "$(reached):$RC"
check "and the message names it" "1" "$(grep -c 'Unsupported architecture: riscv64' "$T/out")"

BLOCK_ARCH="$BLOCK
echo \"ARCH=\$ARCH\""
BLOCK="$BLOCK_ARCH"
case_run arm 2.0.1 false "$LIST" aarch64
check "aarch64 is accepted, as arm64" "yes:0:ARCH=arm64" "$(reached):$RC:$(grep '^ARCH=' "$T/out")"
case_run intel 2.0.1 false "$LIST" x86_64
check "x86_64 is kept as it is" "ARCH=x86_64" "$(grep '^ARCH=' "$T/out")"

exit "$fail"
