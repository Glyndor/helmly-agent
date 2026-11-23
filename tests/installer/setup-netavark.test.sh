#!/usr/bin/env bash
#
# The netavark upgrade of setup-agent.sh: when it is needed, and that what it installs as
# root is the file whose sha256 the release published.
#
# Podman on older distributions ships a netavark that cannot drive nftables. The installer
# then downloads one from upstream, which does not sign its releases, so the sha256 that
# the same release publishes is the only check on the bytes. A binary whose sum is wrong,
# or whose sum cannot be found, must not be installed. `curl` here answers from files.

# shellcheck disable=SC2016,SC1091,SC2154 # the fake programs are single-quoted text that runs later; lib/installer.sh is linted as its own file and sets `fail`
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib/installer.sh"

VERSION_LT="$(function_of "$SETUP" _version_lt)"
BLOCK="$(block "$SETUP" '^if _version_lt .*NETAVARK_REQUIRED' '^unset _netavark_bin')"

# --- _version_lt: a strict "older than", by version order, not by text ------------------
sandbox lt
lt() {
	run_block "$VERSION_LT
_version_lt $1 $2"
	[[ $RC -eq 0 ]] && echo yes || echo no
}
check "1.9.0 is older than 1.10.0 (version order, not text order)" "yes" "$(lt 1.9.0 1.10.0)"
check "1.10.0 is not older than 1.9.0" "no" "$(lt 1.10.0 1.9.0)"
check "a version is not older than itself" "no" "$(lt 1.10.0 1.10.0)"
check "1.4.0 is older than 1.10.0" "yes" "$(lt 1.4.0 1.10.0)"
check "2.0.0 is not older than 1.10.0" "no" "$(lt 2.0.0 1.10.0)"

# case_run <name> <installed version> [sha: good|bad|absent|fetch-fails] [arch] [api version]
case_run() {
	sandbox "$1"
	local sha="${3:-good}" arch="${4:-x86_64}" api="${5-1.15.2}"
	printf 'new netavark binary' | gzip -n > "$T/asset.gz"
	local good
	good="$(sha256sum "$T/asset.gz" | awk '{print $1}')"
	case "$sha" in
		good) printf '%s  netavark.gz\n%s  netavark.aarch64.gz\n' "$good" "$good" > "$T/sums" ;;
		bad) printf '%064d  netavark.gz\n%064d  netavark.aarch64.gz\n' 0 0 > "$T/sums" ;;
		absent) printf '%s  something-else.gz\n' "$good" > "$T/sums" ;;
		fetch-fails) : > "$T/sums" ;;
	esac
	printf 'old netavark binary' > "$T/etc/netavark"
	chmod 700 "$T/etc/netavark"
	fake uname "echo $arch"
	fake curl '
		out=""; url=""
		while [[ $# -gt 0 ]]; do case "$1" in -o) out="$2"; shift 2 ;; http*) url="$1"; shift ;; *) shift ;; esac; done
		case "$url" in
			*/releases/latest) printf "{\"tag_name\": \"v'"$api"'\"}" ;;
			*/sha256sum) [[ "'"$sha"'" == fetch-fails ]] && exit 22; cat "$T/sums" ;;
			*) cp "$T/asset.gz" "$out" ;;
		esac'
	run_block "NETAVARK_REQUIRED=1.10.0
_netavark_bin=/etc/netavark
_netavark_ver=$2
$VERSION_LT
$BLOCK"
}
installed() { cat "$T/etc/netavark"; }

case_run current 1.10.0
check "a netavark that is new enough is left alone" "yes:0:old netavark binary" "$(reached):$RC:$(installed)"
check "and nothing is downloaded" "0" "$(calls curl)"

case_run newer 1.15.0
check "a newer one is left alone as well" "old netavark binary" "$(installed)"

case_run upgrade 1.4.0
check "an older one is replaced by the release the checksum matches" "yes:0:new netavark binary" "$(reached):$RC:$(installed)"
check "and installed as an executable" "755" "$(mode_of "$T/etc/netavark")"
check "from the release of the latest version, for this architecture" "1" "$(grep -c 'releases/download/v1.15.2/netavark.gz ' "$T/calls")"
check "and says the checksum was verified" "1" "$(grep -c 'netavark sha256 verified' "$T/out")"
check "and leaves no download behind" "0" "$(find "$T/tmp" -type f | wc -l)"

case_run mismatch 1.4.0 bad
check "a download whose sha256 differs is refused" "no:1" "$(reached):$RC"
check "and the installed netavark is not touched" "old netavark binary" "$(installed)"
check "and says the sums differ" "1" "$(grep -c 'sha256 mismatch' "$T/out")"
check "and removes what it downloaded" "0" "$(find "$T/tmp" -type f | wc -l)"

case_run absent 1.4.0 absent
check "a checksum list that does not name the asset is refused" "no:1" "$(reached):$RC"
check "and the installed netavark is not touched" "old netavark binary" "$(installed)"
# The message for this case ("Could not fetch sha256 for ...") is never printed: the `grep`
# that picks the line out of the list fails inside a command substitution under
# `set -e -o pipefail`, and the script stops there, silently. The outcome is the right one.

case_run no-list 1.4.0 fetch-fails
check "a checksum list that cannot be fetched is refused" "no" "$(reached)"
check "and the installed netavark is not touched" "old netavark binary" "$(installed)"

case_run arm 1.4.0 good aarch64
check "on arm the arm asset is the one downloaded and checked" "1" "$(grep -c 'netavark.aarch64.gz ' "$T/calls")"
check "and it is installed" "new netavark binary" "$(installed)"

case_run riscv 1.4.0 good riscv64
check "an architecture without an asset is refused" "no:1" "$(reached):$RC"
check "and nothing is downloaded for it" "0" "$(grep -c 'releases/download' "$T/calls" || true)"

case_run no-version 1.4.0 good x86_64 ''
check "a releases answer with no version is refused" "no:1" "$(reached):$RC"
check "and the installed netavark is not touched" "old netavark binary" "$(installed)"

exit "$fail"
