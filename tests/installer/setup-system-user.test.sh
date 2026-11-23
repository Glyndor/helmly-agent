#!/usr/bin/env bash
#
# The account setup-agent.sh creates for the agent, and the sub-id ranges it gives it.
#
# The account is a system account with no home and no login shell, lingering so that the
# rootless containers survive a logout, with 65536 sub-uids and sub-gids of its own. The
# block runs against fake `id`, `useradd` and `loginctl`, and a scratch /etc/subuid.

# shellcheck disable=SC2016,SC1091,SC2154 # the fake programs are single-quoted text that runs later; lib/installer.sh is linted as its own file and sets `fail`
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib/installer.sh"

BLOCK="$(block "$SETUP" '^log_section "Creating system user' '^log_ok "Agent secrets generated"|^# --- Generate agent secrets')"
# The closing line is the comment that opens the next section; it is part of the block.

# case_run <name> <user exists: yes|no> [loginctl: ok|fail]
case_run() {
	sandbox "$1"
	fake id '[[ "'"$2"'" == yes ]]'
	fake useradd
	fake loginctl '[[ "'"${3:-ok}"'" == ok ]]'
	run_block "$BLOCK" HELMLY_AGENT_USER=helmly-agent
}

case_run new no
check "the block runs to its end" "yes:0" "$(reached):$RC"
check "a missing account is created, as a system account, with no home and no login shell" \
	"useradd --system --no-create-home --shell /usr/sbin/nologin --comment Helmly Agent service user helmly-agent" \
	"$(grep '^useradd' "$T/calls")"
check "and it lingers, so its rootless containers outlive a login" "loginctl enable-linger helmly-agent" "$(grep '^loginctl' "$T/calls")"
check "and gets 65536 sub-uids from 1000000" "helmly-agent:1000000:65536" "$(cat "$T/etc/subuid")"
check "and 65536 sub-gids from the same start" "helmly-agent:1000000:65536" "$(cat "$T/etc/subgid")"

case_run existing yes
check "an account that exists is not created again" "0" "$(calls useradd)"
check "and says it was skipped" "1" "$(grep -c 'already exists' "$T/out")"
check "but still lingers" "1" "$(calls loginctl)"

case_run twice no
run_block "$BLOCK" HELMLY_AGENT_USER=helmly-agent
check "running it twice leaves one sub-uid line" "1" "$(grep -c '^helmly-agent:' "$T/etc/subuid")"
check "and one sub-gid line" "1" "$(grep -c '^helmly-agent:' "$T/etc/subgid")"

case_run other-range no
printf 'someone:100000:65536\n' > "$T/etc/subuid"
run_block "$BLOCK" HELMLY_AGENT_USER=helmly-agent
check "an existing /etc/subuid keeps its lines and gains the agent's" "someone:100000:65536 helmly-agent:1000000:65536" "$(tr '\n' ' ' < "$T/etc/subuid" | sed 's/ $//')"

case_run linger-fails no fail
check "a linger that fails does not stop the setup" "yes:0" "$(reached):$RC"

exit "$fail"
