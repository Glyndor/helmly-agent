#!/usr/bin/env bash
#
# Characterisation test for `_verify_release_sig` in setup-agent.sh.
#
# This is the installer's only security control: it decides whether the
# binary about to be installed as root was signed by the org. Everything
# else in the script is plumbing around that decision.
#
# It is written BEFORE the split in #153, on purpose. A test written
# against behaviour survives a refactor and is the only thing that makes
# "the 880 lines still do the same" demonstrable rather than asserted by
# reading. After the split, re-point EXTRACT at wherever the function
# lands; every assertion below should still hold, and that equivalence is
# the point.
#
# It asserts on what the check REJECTS, and each rejection names which
# one. The org has already paid for the other kind: in `apt`, three tests
# pinned the ORDER of the installer's steps by line number, and changing
# `grep -qx` to `grep -q` left the installer accepting any key with all
# four green. A test that pins the position of a control does not touch
# the control.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/setup-agent.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail=0
check() { # check <name> <expected> <actual>
	if [[ "$2" == "$3" ]]; then
		printf 'ok   %s\n' "$1"
	else
		printf 'FAIL %s\n       expected: %s\n       actual:   %s\n' "$1" "$2" "$3"
		fail=1
	fi
}

# --- Extract the verifier ------------------------------------------------
#
# The control lives in a python heredoc inside the function. Extracting it
# rather than sourcing the script is what makes this runnable at all:
# setup-agent.sh is linear, exits unless EUID is 0, and starts mutating the
# host within seventy lines.
sed -n "/^_verify_release_sig() {/,/^}/p" "$SCRIPT" \
	| sed -n "/<<'PYEOF'/,/^PYEOF$/p" \
	| sed '1d;$d' > "$WORK/verify.py"

[[ -s "$WORK/verify.py" ]] || {
	echo "FAIL could not extract the verifier from $SCRIPT; the markers moved" >&2
	exit 1
}

# --- Fixtures ------------------------------------------------------------
python3 - "$WORK" <<'PY'
import base64, os, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
w = sys.argv[1]
good = Ed25519PrivateKey.generate()
other = Ed25519PrivateKey.generate()
payload = os.urandom(4096)
open(f"{w}/artifact", "wb").write(payload)
open(f"{w}/artifact.sig", "wb").write(good.sign(payload))
open(f"{w}/artifact.wrongkey.sig", "wb").write(other.sign(payload))
raw = lambda k: k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
open(f"{w}/good.pub", "w").write(base64.b64encode(raw(good)).decode())
open(f"{w}/other.pub", "w").write(base64.b64encode(raw(other)).decode())
PY

GOOD_PUB="$(cat "$WORK/good.pub")"

# Run the extracted verifier with slot 0 and slot 1 substituted.
run_verify() { # run_verify <slot0> <slot1> <file> <sig>; echoes the exit code
	local slot0="$1" slot1="$2" file="$3" sig="$4"
	python3 - "$slot0" "$slot1" "$file" "$sig" "$WORK/verify.py" <<'PY' >/dev/null 2>&1
import re, sys, runpy, os
slot0, slot1, f, s, verifier = sys.argv[1:6]
src = open(verifier).read()
src = re.sub(r'PUB_KEYS_B64 = \[.*?\]',
             'PUB_KEYS_B64 = [%r, %r]' % (slot0, slot1), src, flags=re.S)
tmp = f + ".verifier.py"
open(tmp, "w").write(src)
sys.argv = [tmp, f, s]
runpy.run_path(tmp, run_name="__main__")
PY
	echo $?
}

# --- The assertions ------------------------------------------------------

check "a signature from the pinned key is accepted" \
	0 "$(run_verify "$GOOD_PUB" "" "$WORK/artifact" "$WORK/artifact.sig")"

check "a signature from a DIFFERENT key is rejected" \
	1 "$(run_verify "$GOOD_PUB" "" "$WORK/artifact" "$WORK/artifact.wrongkey.sig")"

cp "$WORK/artifact" "$WORK/tampered"
printf 'x' | dd of="$WORK/tampered" bs=1 seek=100 conv=notrunc status=none
check "a tampered payload is rejected under a valid signature" \
	1 "$(run_verify "$GOOD_PUB" "" "$WORK/tampered" "$WORK/artifact.sig")"

head -c 32 "$WORK/artifact.sig" > "$WORK/short.sig"
check "a truncated signature is rejected" \
	1 "$(run_verify "$GOOD_PUB" "" "$WORK/artifact" "$WORK/short.sig")"

# The two-slot contract. Slot 1 carries the incoming key during a rotation
# and is empty otherwise, so an empty slot must be SKIPPED and must never
# count as a match.
check "an empty slot 1 does not admit anything" \
	1 "$(run_verify "$(cat "$WORK/other.pub")" "" "$WORK/artifact" "$WORK/artifact.sig")"

check "slot 1 verifies during a rotation" \
	0 "$(run_verify "$(cat "$WORK/other.pub")" "$GOOD_PUB" "$WORK/artifact" "$WORK/artifact.sig")"

# The one that matters most: with nothing to trust, refuse. A verifier that
# passes when both slots are empty would accept every binary on earth.
check "both slots empty fails closed" \
	1 "$(run_verify "" "" "$WORK/artifact" "$WORK/artifact.sig")"

exit "$fail"
