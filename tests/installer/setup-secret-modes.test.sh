#!/usr/bin/env bash
#
# What setup-agent.sh writes for the agent's configuration, and who can read it.
#
# The environment file names where each secret is; the secrets themselves go into
# credential files that systemd hands to the service. Every one of them must be readable by
# root only, and no secret may land in the environment file, which is the one a person is
# most likely to paste into a bug report.

# shellcheck disable=SC2016,SC1091,SC2154 # lib/ is linted as its own file and sets `fail`
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib/installer.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../lib/setup_config_block.sh"

run_config plain
check "the block runs to its end" "yes:0" "$(reached):$RC"

check "the environment file is root-only" "600" "$(mode_of "$ENVFILE")"
for f in internal-token helmly-dashboard-pubkey sync-token tls-cert.der tls-key.der tls-ca.der; do
	check "the credential $f is root-only" "600" "$(mode_of "$CRED/$f")"
done

check "the internal token is stored as given" "internal-token-value" "$(cat "$CRED/internal-token")"
check "the dashboard public key is stored as given" "dashboard-pubkey-value" "$(cat "$CRED/helmly-dashboard-pubkey")"
check "the sync token is stored as given" "sync-token-value" "$(cat "$CRED/sync-token")"
check "the three mTLS files are decoded, not stored as base64" "cert-bytes key-bytes ca-bytes" "$(cat "$CRED/tls-cert.der") $(cat "$CRED/tls-key.der") $(cat "$CRED/tls-ca.der")"

check "no secret value is written into the environment file" "0" \
	"$(grep -c 'internal-token-value\|dashboard-pubkey-value\|sync-token-value\|cert-bytes\|key-bytes\|ca-bytes' "$ENVFILE" || true)"
check "the environment file points each secret at a credential of the service" "8" \
	"$(grep -c '^[A-Z_]*_FILE=/run/credentials/helmly-agent.service/' "$ENVFILE")"
check "it gives the agent its identity" "1" "$(grep -c '^AGENT_ID=0190b8a0-0000-7000-8000-000000000001$' "$ENVFILE")"
check "it listens on the loopback only, on the agent port" "LISTEN_ADDR=127.0.0.1:9090" "$(grep '^LISTEN_ADDR=' "$ENVFILE")"
check "it names the dashboard through its tunnel address" "DASHBOARD_URL=http://10.100.0.1:8080" "$(grep '^DASHBOARD_URL=' "$ENVFILE")"
check "and has no dashboard port on a plain agent" "0" "$(grep -c '^DASHBOARD_PORT=' "$ENVFILE" || true)"

run_config dashboard yes
check "on the dashboard host the panel port is named" "DASHBOARD_PORT=19443" "$(grep '^DASHBOARD_PORT=' "$ENVFILE")"
check "and the file is still root-only" "600" "$(mode_of "$ENVFILE")"

# The tokens were held in shell variables of the installer; each is overwritten with random
# bytes from the agent binary before it is dropped.
check "the shell copies of the internal token and the sync token are overwritten" "2" "$(grep -c '^helmly-agent gen-rand 32$' "$T/calls")"

exit "$fail"
