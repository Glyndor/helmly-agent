#!/usr/bin/env bash
#
# Characterisation test for `_write_tls_credentials` in setup-agent.sh.
#
# The agent fails closed without TLS_CERT_DER_FILE, TLS_KEY_DER_FILE and
# TLS_CA_CERT_DER_FILE (internal/main.rs). The dashboard already issues all
# three at VPS registration and returns them base64-encoded; until now
# nothing on this side consumed them, which is #147.
#
# Written before the function, and red before green. The assertions that
# matter are not "the files appear": they are that a HALF-provisioned host
# is impossible. A machine with two of the three files looks provisioned
# and will not start, which is worse than one that was never touched.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/setup-agent.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail=0
check() {
	if [[ "$2" == "$3" ]]; then
		printf 'ok   %s\n' "$1"
	else
		printf 'FAIL %s\n       expected: %s\n       actual:   %s\n' "$1" "$2" "$3"
		fail=1
	fi
}

# Extract the function and the helpers it needs, then source that. The script
# itself is linear and exits unless EUID is 0, so it cannot be sourced.
sed -n "/^_write_tls_credentials() {/,/^}/p" "$SCRIPT" > "$WORK/fn.sh"
[[ -s "$WORK/fn.sh" ]] || {
	echo "FAIL _write_tls_credentials not found in $SCRIPT" >&2
	exit 1
}
# The extracted function calls these. shellcheck cannot see that, because
# the call sites arrive through `source` at run time, so it reports both
# SC2329 "never invoked" and SC2317 "unreachable" on them. Which of the two
# it reports depends on the version: CI pins 0.11.0 and says SC2329, the
# 0.10.0 I had locally says SC2317, so "shellcheck clean" without naming a
# version is not a claim about anything. They are invoked; silencing it here is narrower
# than not defining them, which would make the function fail on its own
# error paths and quietly pass the rejection tests for the wrong reason.
# shellcheck disable=SC2329,SC2317
log_error() { :; }
# shellcheck disable=SC2329,SC2317
log_ok() { :; }
# shellcheck source=/dev/null
source "$WORK/fn.sh"

b64() { printf '%s' "$1" | base64 -w0; }
CERT="$(b64 'cert-der-bytes')"
KEY="$(b64 'key-der-bytes')"
CA="$(b64 'ca-der-bytes')"

# --- the happy path ------------------------------------------------------
DIR="$WORK/ok"
mkdir -p "$DIR"
_write_tls_credentials "$CERT" "$KEY" "$CA" "$DIR" && rc=0 || rc=$?
check "three valid blobs are accepted" 0 "$rc"
check "the certificate is written"     "cert-der-bytes" "$(cat "$DIR/tls-cert.der" 2>/dev/null)"
check "the key is written"             "key-der-bytes"  "$(cat "$DIR/tls-key.der" 2>/dev/null)"
check "the CA is written"              "ca-der-bytes"   "$(cat "$DIR/tls-ca.der" 2>/dev/null)"
for f in tls-cert.der tls-key.der tls-ca.der; do
	check "$f is 0600" "600" "$(stat -c '%a' "$DIR/$f" 2>/dev/null)"
done

# --- rejection, and nothing written --------------------------------------
#
# This is the half-provisioned case. Validation has to happen before the
# first write, or a bad third argument leaves two good files behind and the
# host looks provisioned and does not start.
DIR="$WORK/badca"
mkdir -p "$DIR"
_write_tls_credentials "$CERT" "$KEY" "not!valid!base64" "$DIR" && rc=0 || rc=$?
check "an invalid CA blob is rejected" 1 "$rc"
check "and NOTHING is written when it is rejected" \
	"0" "$(find "$DIR" -type f | wc -l)"

DIR="$WORK/emptykey"
mkdir -p "$DIR"
_write_tls_credentials "$CERT" "" "$CA" "$DIR" && rc=0 || rc=$?
check "an empty key blob is rejected" 1 "$rc"
check "and nothing is written for an empty blob" \
	"0" "$(find "$DIR" -type f | wc -l)"

# --- refusing to clobber -------------------------------------------------
#
# Re-running provisioning must not silently replace material the dashboard
# has already been told about.
DIR="$WORK/exists"
mkdir -p "$DIR"
printf 'original' > "$DIR/tls-cert.der"
_write_tls_credentials "$CERT" "$KEY" "$CA" "$DIR" && rc=0 || rc=$?
check "an existing credential is not overwritten" 1 "$rc"
check "and the original survives" "original" "$(cat "$DIR/tls-cert.der")"

exit "$fail"
