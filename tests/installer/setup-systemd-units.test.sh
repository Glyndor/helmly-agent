#!/usr/bin/env bash
#
# The two systemd units setup-agent.sh installs: the database container and the agent.
#
# What matters in them is a short list: the agent starts only after the database is up,
# it gets every secret as a systemd credential and never as a plain file path the service
# reads by itself, it restarts when it dies, and both units are enabled after the manager
# has been told they exist.

# shellcheck disable=SC2016,SC1091,SC2154 # lib/ is linted as its own file and sets `fail`
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib/installer.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../lib/setup_config_block.sh"

run_config units
unit() { norm < "$AGENT_UNIT"; }

check "the block runs to its end" "yes:0" "$(reached):$RC"

# --- the database unit -------------------------------------------------------
check "the database unit starts the existing container, it does not create one" "ExecStart=/usr/bin/podman start helmly-agent-postgres" \
	"$(grep '^ExecStart=' "$PG_UNIT")"
check "and stops it with a 30 second grace" "ExecStop=/usr/bin/podman stop -t 30 helmly-agent-postgres" "$(grep '^ExecStop=' "$PG_UNIT")"
check "and stays active while the container runs" "Type=oneshot RemainAfterExit=yes" "$(grep '^Type=\|^RemainAfterExit=' "$PG_UNIT" | tr '\n' ' ' | sed 's/ $//')"
check "and is wanted at boot" "WantedBy=multi-user.target" "$(grep '^WantedBy=' "$PG_UNIT")"

# --- the agent unit ------------------------------------------------------------
check "the agent waits for the database unit" "After=network.target helmly-agent-postgres.service" "$(unit | grep '^After=')"
check "and does not run without it" "Requires=network.target helmly-agent-postgres.service" "$(unit | grep '^Requires=')"
check "it runs as root, which package management, nftables and self-update need" "User=root Group=root" \
	"$(unit | grep '^User=\|^Group=' | tr '\n' ' ' | sed 's/ $//')"
check "it reads its environment from the file the block wrote" "EnvironmentFile=/etc/glyndor/helmly/agent.env" "$(unit | grep '^EnvironmentFile=')"
check "and runs the installed binary" "ExecStart=/etc/glyndor/helmly/bin/helmly-agent" "$(unit | grep '^ExecStart=')"
check "it comes back after a failure, five seconds later" "Restart=always RestartSec=5s" \
	"$(unit | grep '^Restart=\|^RestartSec=' | tr '\n' ' ' | sed 's/ $//')"
check "it has a private /tmp" "PrivateTmp=yes" "$(unit | grep '^PrivateTmp=')"
check "and is wanted at boot" "WantedBy=multi-user.target" "$(unit | grep '^WantedBy=')"

EXPECTED="database-url helmly-dashboard-pubkey helmly-kek helmly-wg-psk internal-token sync-token tls-ca.der tls-cert.der tls-key.der"
check "it loads exactly nine credentials: the eight the environment file points to and the pre-shared key" "$EXPECTED" \
	"$(unit | sed -n 's/^LoadCredential=\([^:]*\):.*/\1/p' | sort | tr '\n' ' ' | sed 's/ $//')"
check "each one from the root-only credentials directory" "9" \
	"$(unit | grep -c '^LoadCredential=[^:]*:-\?/etc/glyndor/helmly/credentials/')"
check "and the WireGuard pre-shared key is the only optional one, loaded with a leading dash" "LoadCredential=helmly-wg-psk:-/etc/glyndor/helmly/credentials/helmly-wg-psk" \
	"$(unit | grep ':-/')"
# Every credential the environment file names is one the unit loads.
missing=""
while read -r name; do
	unit | grep -q "^LoadCredential=$name:" || missing="$missing $name"
done < <(sed -n 's#^[A-Z_]*_FILE=/run/credentials/helmly-agent.service/##p' "$ENVFILE")
check "every credential named in the environment file is loaded by the unit" "" "$missing"

# --- registering them ----------------------------------------------------------
check "the manager is told to reload before the units are enabled" "daemon-reload enable enable" \
	"$(awk '$1 == "systemctl" { print $2 }' "$T/calls" | tr '\n' ' ' | sed 's/ $//')"
check "the database unit is enabled" "1" "$(grep -c '^systemctl enable helmly-agent-postgres.service$' "$T/calls")"
check "and the agent unit is enabled" "1" "$(grep -c '^systemctl enable helmly-agent.service$' "$T/calls")"
check "neither is started by this block" "0" "$(grep -c '^systemctl start' "$T/calls" || true)"

exit "$fail"
