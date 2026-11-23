#!/usr/bin/env bash
#
# The download step of update-agent.sh, at the place it calls the signature check: what it
# fetches, where it puts it, and what it leaves behind when the check says no.
#
# The check itself is tested in update-agent-signature.test.sh. Here it is a function that
# answers from a switch, because what this test pins is the decision around it: a binary
# that fails the check is deleted, the installed one is not touched, and the script stops.

# shellcheck disable=SC2016,SC1091,SC2154 # the fake programs are single-quoted text that runs later; lib/installer.sh is linted as its own file and sets `fail`
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib/installer.sh"

BLOCK="$(block "$UPDATE" '^RELEASE_BASE=' '^log_ok "Agent binary verified"')"

# case_run <name> <verdict: pass|fail> [curl failing on: binary|sig|none]
case_run() {
	sandbox "$1"
	local bin="$T/etc/glyndor/helmly/bin"
	mkdir -p "$bin"
	printf 'installed binary' > "$bin/helmly-agent"
	fake curl '
		out=""; url=""
		while [[ $# -gt 0 ]]; do case "$1" in -o) out="$2"; shift 2 ;; http*) url="$1"; shift ;; *) shift ;; esac; done
		case "$url" in
			*.sig) [[ "'"${3:-none}"'" == sig ]] && exit 22; printf "signature bytes" > "$out" ;;
			*) [[ "'"${3:-none}"'" == binary ]] && exit 22; printf "downloaded binary" > "$out" ;;
		esac'
	local text
	text="_verify_release_sig() { [[ \"$2\" == pass ]]; }
log_section() { :; }
GITHUB_REPO=Glyndor/helmly-agent; LATEST_TAG=v2.0.2; ARCH=arm64
BIN_DIR=/etc/glyndor/helmly/bin
$BLOCK"
	run_block "$text"
	BIN="$bin"
}

case_run good pass
check "a binary that passes the check is accepted" "yes:0" "$(reached):$RC"
check "and is made executable" "755" "$(mode_of "$BIN/helmly-agent.new")"
check "and the signature file is removed" "no" "$([[ -e "$BIN/helmly-agent.new.sig" ]] && echo yes || echo no)"
check "and the installed binary is not touched yet" "installed binary" "$(cat "$BIN/helmly-agent")"
check "and it is fetched from the release of the latest tag, for the architecture" "1" "$(grep -c 'releases/download/v2.0.2/helmly-agent-linux-arm64 ' "$T/calls")"
check "with its signature from the same release" "1" "$(grep -c 'releases/download/v2.0.2/helmly-agent-linux-arm64.sig ' "$T/calls")"
check "over https" "2" "$(grep -c ' https://github.com/Glyndor/helmly-agent/' "$T/calls")"

case_run bad fail
check "a binary that fails the check stops the update" "no:1" "$(reached):$RC"
check "and is deleted" "no" "$([[ -e "$BIN/helmly-agent.new" ]] && echo yes || echo no)"
check "and so is its signature" "no" "$([[ -e "$BIN/helmly-agent.new.sig" ]] && echo yes || echo no)"
check "and the installed binary is intact" "installed binary" "$(cat "$BIN/helmly-agent")"
check "and says the current version is intact" "1" "$(grep -c 'current version intact' "$T/out")"

case_run no-binary pass binary
check "a binary that cannot be downloaded stops the script before any check" "no" "$(reached)"
check "with a failure status" "1" "$([[ $RC -ne 0 ]] && echo 1 || echo 0)"
check "and the installed binary is intact" "installed binary" "$(cat "$BIN/helmly-agent")"

case_run no-sig pass sig
check "a signature that cannot be downloaded stops the script, even if the check would pass" "no" "$(reached)"
check "with a failure status" "1" "$([[ $RC -ne 0 ]] && echo 1 || echo 0)"
check "and the installed binary is intact" "installed binary" "$(cat "$BIN/helmly-agent")"

exit "$fail"
