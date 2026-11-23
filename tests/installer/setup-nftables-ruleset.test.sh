#!/usr/bin/env bash
#
# The firewall setup-agent.sh puts on the host before the agent starts.
#
# The agent replaces this ruleset with its own on startup, so it is what protects the
# machine in the first seconds and on every boot until then. The properties are few and
# all of them are about what is closed: the input and forward chains drop by default, SSH
# is rate limited per source, the agent API is reachable from the tunnel interface only,
# and the dashboard panel port is open on the dashboard host and nowhere else. `nft` here
# keeps the file it is given, so the test reads the ruleset that would have been loaded.

# shellcheck disable=SC2016,SC1091,SC2154 # the fake programs are single-quoted text that runs later; lib/installer.sh is linted as its own file and sets `fail`
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib/installer.sh"

BLOCK="$(block "$SETUP" '^log_section "Configuring nftables \(agent\)"' '^systemctl enable nftables')"

# case_run <name> <dashboard host: true|false> [nftables.conf: absent|plain|already-included]
case_run() {
	sandbox "$1"
	fake nft 'if [[ "$1" == "-f" ]]; then cp "$2" "$T/loaded.conf"; fi'
	fake systemctl
	case "${3:-absent}" in
		plain) printf '#!/usr/sbin/nft -f\nflush ruleset\n' > "$T/etc/nftables.conf" ;;
		already-included) printf 'include "/etc/nftables-helmly-agent.conf"\n' > "$T/etc/nftables.conf" ;;
	esac
	run_block "$BLOCK" IS_DASHBOARD_VPS="$2" WG_PORT=51820 WG_IFACE=wg-helmly-agent AGENT_PORT=9090
	RULES="$T/etc/nftables-helmly-agent.conf"
}
chain() { awk -v name="$1" '$1 == "chain" && $2 == name { on = 1 } on { print } on && /^    }/ { exit }' "$RULES"; }

case_run agent false
check "the block runs to its end" "yes:0" "$(reached):$RC"
check "the ruleset is loaded, and it is the file that was written" "yes" "$(cmp -s "$RULES" "$T/loaded.conf" && echo yes || echo no)"
check "the file is loaded with nft -f" "1" "$(grep -c '^nft -f ' "$T/calls")"

check "it starts by removing the table of an earlier install, then makes its own" "destroy table inet helmly-agent|add table inet helmly-agent" \
	"$(sed -n '1p;2p' "$RULES" | paste -sd'|')"

check "the input chain drops by default" "1" "$(chain helmly-base | grep -c 'hook input priority 0; policy drop;')"
check "and ends with an explicit drop" "drop" "$(chain helmly-base | grep -v '^$' | tail -n 2 | head -n 1 | tr -d ' ')"
check "the forward chain drops by default" "1" "$(chain helmly-forward | grep -c 'hook forward priority 0; policy drop;')"
check "the output chain is open" "1" "$(chain helmly-output | grep -c 'hook output priority 0; policy accept;')"
check "no chain that filters input or forward accepts by default" "0" \
	"$( { chain helmly-base; chain helmly-forward; } | grep -c 'policy accept' || true)"

check "established traffic and loopback are accepted" "2" "$(chain helmly-base | grep -c 'iif lo accept\|ct state established,related accept')"
check "SSH is limited to 10 new connections a minute for each source address" "1" \
	"$(chain helmly-base | grep -c 'tcp dport 22 ct state new meter ssh_throttle { ip saddr limit rate 10/minute burst 20 packets } accept')"
check "WireGuard is open on its port" "1" "$(chain helmly-base | grep -c 'udp dport 51820 accept')"
check "the agent API is open on the tunnel interface only" "1" \
	"$(chain helmly-base | grep -c 'iifname "wg-helmly-agent" tcp dport 9090 accept')"
check "and the agent port is named nowhere else" "1" "$(grep -c 'dport 9090' "$RULES")"
check "an agent host does not open the panel port" "0" "$(grep -c 'dport 19443' "$RULES" || true)"
check "nor the DNS of the container networks" "0" "$(grep -c 'dport 53' "$RULES" || true)"
check "nor forwards the dashboard tunnel" "0" "$(grep -c 'oifname "wg-helmly-dash"' "$RULES" || true)"
check "containers may reach out" "1" "$(chain helmly-forward | grep -c 'iifname "podman\*" accept')"

check "without /etc/nftables.conf there is nothing to include it from, and none is created" "no" "$([[ -e "$T/etc/nftables.conf" ]] && echo yes || echo no)"

case_run dashboard true
check "the dashboard host opens the panel port, for new connections" "1" "$(chain helmly-base | grep -c 'tcp dport 19443 ct state new accept')"
check "and the DNS of the container networks, from the container interfaces" "2" \
	"$(chain helmly-base | grep -c 'iifname "podman\*" \(udp\|tcp\) dport 53 accept')"
check "and forwards the dashboard tunnel both ways" "2" "$(chain helmly-forward | grep -c '\(oifname\|iifname\) "wg-helmly-dash" accept')"
check "and still drops input by default" "1" "$(chain helmly-base | grep -c 'policy drop;')"

case_run plain-conf false plain
check "an existing /etc/nftables.conf gets one include of the ruleset, so it survives a reboot" 'include "/etc/nftables-helmly-agent.conf"' \
	"$(sed "s#$T##" "$T/etc/nftables.conf" | grep '^include')"
check "and only one" "1" "$(grep -c '^include' "$T/etc/nftables.conf")"
case_run included false already-included
check "a conf that includes it already is not given a second include" "1" "$(grep -c 'helmly-agent' "$T/etc/nftables.conf")"

check "the ruleset is made persistent: nftables is enabled at boot" "1" "$(grep -c '^systemctl enable nftables$' "$T/calls")"

exit "$fail"
