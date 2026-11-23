#!/usr/bin/env bash
# Runs the block of setup-agent.sh that writes the agent's environment file, its
# credentials and its two systemd units, in a scratch tree, for the tests that read what it
# wrote (setup-secret-modes.test.sh and setup-systemd-units.test.sh).
#
# Source it after lib/installer.sh. `run_config` leaves the scratch tree in $T and the
# status in $RC; `norm` turns the scratch prefix back into the real path, so an assertion
# can say /etc/glyndor/helmly/... as the script does.

# shellcheck disable=SC2034,SC2329,SC2317 # read and called by the sourcing tests
CONFIG_BLOCK="$(block "$SETUP" '^log_section "Writing agent configuration"' '^log_ok "Services installed')"
TLS_FUNCTION="$(function_of "$SETUP" _write_tls_credentials)"

norm() { sed "s#$T##g"; }

# run_config <name> [dashboard: yes|no]
run_config() {
	sandbox "$1"
	mkdir -p "$T/etc/glyndor/helmly/credentials" "$T/etc/glyndor/helmly/bin" "$T/etc/systemd/system"
	if [[ "${2:-no}" == yes ]]; then
		mkdir -p "$T/etc/glyndor/helmly/nginx"
		: > "$T/etc/glyndor/helmly/nginx/default.conf"
	fi
	fake systemctl
	# The agent binary only has to answer `gen-rand`, which the block calls to overwrite a secret
	# it no longer needs; the call is written down in $T/calls.
	# shellcheck disable=SC2016 # the text of a program, expanded when it runs
	printf '#!/usr/bin/env bash\nprintf "helmly-agent %%s\\n" "$*" >> "$T/calls"\necho overwritten\n' > "$T/etc/glyndor/helmly/bin/helmly-agent"
	chmod +x "$T/etc/glyndor/helmly/bin/helmly-agent"
	local b64
	b64() { printf '%s' "$1" | base64 -w0; }
	run_block "$TLS_FUNCTION
HELMLY_DIR=/etc/glyndor/helmly
AGENT_CONF=/etc/glyndor/helmly/agent.env
BINARY_PATH=/etc/glyndor/helmly/bin/helmly-agent
AGENT_ID=0190b8a0-0000-7000-8000-000000000001
AGENT_PORT=9090
DASHBOARD_WG_IP=10.100.0.1
INTERNAL_TOKEN=internal-token-value
DASHBOARD_SIGN_PUBKEY=dashboard-pubkey-value
SYNC_TOKEN=sync-token-value
TLS_CERT_B64=$(b64 cert-bytes)
TLS_KEY_B64=$(b64 key-bytes)
TLS_CA_B64=$(b64 ca-bytes)
$CONFIG_BLOCK"
	CRED="$T/etc/glyndor/helmly/credentials"
	ENVFILE="$T/etc/glyndor/helmly/agent.env"
	AGENT_UNIT="$T/etc/systemd/system/helmly-agent.service"
	PG_UNIT="$T/etc/systemd/system/helmly-agent-postgres.service"
}
