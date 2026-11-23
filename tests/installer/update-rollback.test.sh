#!/usr/bin/env bash
#
# The swap of update-agent.sh and what it does when the new binary does not come up.
#
# The updater keeps the running binary as `.prev`, moves the new one in, restarts the
# service and, if the restart fails or the service is not active afterwards, puts `.prev`
# back. This is the only thing that stops a bad release from leaving the agent down, and it
# had no test. `systemctl` here is a program that answers from two switches, so each way
# the service can fail is a case.

# shellcheck disable=SC2016,SC1091,SC2154 # the fake programs are single-quoted text that runs later; lib/installer.sh is linted as its own file and sets `fail`
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib/installer.sh"

BLOCK="$(block "$UPDATE" '^log_section "Deploying agent binary"' '^log_ok "helmly-agent running with new binary"')"

# case_run <name> <restart: ok|fail> <active: yes|no> [keep prev: yes|no]
case_run() {
	sandbox "$1"
	local bin="$T/etc/glyndor/helmly/bin"
	mkdir -p "$bin"
	printf 'old binary' > "$bin/helmly-agent"
	printf 'new binary' > "$bin/helmly-agent.new"
	fake systemctl '
		case "$1" in
			restart) [[ "'"$2"'" == ok ]] || { [[ -e "$T/restarted" ]] && exit 0; touch "$T/restarted"; exit 1; } ;;
			is-active) [[ "'"$3"'" == yes ]] ;;
		esac'
	fake sleep
	fake journalctl
	run_block "$BLOCK" BINARY_PATH="$bin/helmly-agent" AGENT_TMP="$bin/helmly-agent.new"
	BIN="$bin/helmly-agent"
}
content() { cat "$1" 2> /dev/null || echo MISSING; }

case_run ok ok yes
check "a service that comes up keeps the new binary" "yes:0:new binary" "$(reached):$RC:$(content "$BIN")"
check "and the previous one is kept as .prev" "old binary" "$(content "$BIN.prev")"
check "and the service is restarted once" "1" "$(grep -c '^systemctl restart helmly-agent.service' "$T/calls")"

case_run restart-fails fail yes
check "a failed restart stops the update with an error" "no:1" "$(reached):$RC"
check "and puts the previous binary back" "old binary" "$(content "$BIN")"
check "and the copy it restored from is gone, not left to be restored twice" "MISSING" "$(content "$BIN.prev")"
check "and restarts the service again, on the old binary" "2" "$(grep -c '^systemctl restart helmly-agent.service' "$T/calls")"
check "and says it was restored" "1" "$(grep -c 'Previous version restored' "$T/out")"

case_run inactive ok no
check "a service that is not active after the restart stops the update" "no:1" "$(reached):$RC"
check "and puts the previous binary back" "old binary" "$(content "$BIN")"
check "and asks for a second restart" "2" "$(grep -c '^systemctl restart helmly-agent.service' "$T/calls")"
check "and says it was restored" "1" "$(grep -c 'Previous version restored' "$T/out")"

case_run no-binary-to-keep ok yes
rm -f "$BIN" "$BIN.prev"
printf 'new binary' > "$T/etc/glyndor/helmly/bin/helmly-agent.new"
run_block "$BLOCK" BINARY_PATH="$BIN" AGENT_TMP="$T/etc/glyndor/helmly/bin/helmly-agent.new"
check "with nothing to keep, the swap still happens" "yes:0:new binary" "$(reached):$RC:$(content "$BIN")"
check "and no .prev is invented" "MISSING" "$(content "$BIN.prev")"

exit "$fail"
