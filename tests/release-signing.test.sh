#!/usr/bin/env bash
#
# Tests for the two scripts that sign a release and check the signature before
# anything is published: .github/scripts/sign.py and .github/scripts/verify-release.py.
#
# A release is immutable, so these are the last place a bad signature can be
# caught. Each case asserts the exit code and, for a refusal, the message that
# names the reason, because both scripts exit 1 for several reasons.

set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIGN="$ROOT/.github/scripts/sign.py"
VERIFY="$ROOT/.github/scripts/verify-release.py"
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
code() { # code <command...>: the exit code, output in $WORK/out
	local rc=0
	"$@" > "$WORK/out" 2>&1 || rc=$?
	echo "$rc"
}
said() { grep -q -- "$1" "$WORK/out" && echo yes || echo no; }

# Two keys: the seed (base64 of 32 bytes) the signer reads, and the public halves.
python3 - "$WORK" << 'PY'
import base64, sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

w = sys.argv[1]
for name in ("release", "other"):
	key = Ed25519PrivateKey.generate()
	seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
	pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
	open(f"{w}/{name}.seed", "w").write(base64.b64encode(seed).decode())
	open(f"{w}/{name}.pub", "w").write(base64.b64encode(pub).decode())
PY
RELEASE_SEED="$(cat "$WORK/release.seed")"
RELEASE_PUB="$(cat "$WORK/release.pub")"
OTHER_PUB="$(cat "$WORK/other.pub")"
printf 'the bytes of a release artifact' > "$WORK/artifact"

# --- sign.py -----------------------------------------------------------------
check "sign.py with no argument exits 1 and prints its usage" "1" "$(code python3 "$SIGN")"
check "the usage names the key variable" "yes" "$(said GLYNDOR_RELEASE_ED25519_KEY)"

check "sign.py without the key in the environment exits 1" "1" "$(code env -u GLYNDOR_RELEASE_ED25519_KEY python3 "$SIGN" "$WORK/artifact")"
check "it says the key is not set" "yes" "$(said 'GLYNDOR_RELEASE_ED25519_KEY is not set')"
check "and writes no signature" "no" "$([[ -e "$WORK/artifact.sig" ]] && echo yes || echo no)"

check "sign.py with an empty key exits 1" "1" "$(code env GLYNDOR_RELEASE_ED25519_KEY= python3 "$SIGN" "$WORK/artifact")"

check "sign.py signs with the key from the environment" "0" "$(code env GLYNDOR_RELEASE_ED25519_KEY="$RELEASE_SEED" python3 "$SIGN" "$WORK/artifact")"
check "the signature is 64 bytes" "64" "$(wc -c < "$WORK/artifact.sig" | tr -d ' ')"
check "the key is never printed" "no" "$(said "$RELEASE_SEED")"

check "sign.py writes to the output path it is given" "0" "$(code env GLYNDOR_RELEASE_ED25519_KEY="$RELEASE_SEED" python3 "$SIGN" "$WORK/artifact" "$WORK/elsewhere.sig")"
check "the two signatures are the same bytes (Ed25519 is deterministic)" "same" "$(cmp -s "$WORK/artifact.sig" "$WORK/elsewhere.sig" && echo same || echo different)"

check "sign.py on a file that does not exist fails" "1" "$(code env GLYNDOR_RELEASE_ED25519_KEY="$RELEASE_SEED" python3 "$SIGN" "$WORK/missing")"

# --- verify-release.py ----------------------------------------------------------
check "verify-release.py with too few arguments exits 1" "1" "$(code python3 "$VERIFY" "$WORK/artifact")"

check "a signature from the pinned key verifies" "0" "$(code python3 "$VERIFY" "$WORK/artifact" "$RELEASE_PUB")"
check "it says what it verified" "yes" "$(said 'verified')"

check "the same key without its '=' padding verifies" "0" "$(code python3 "$VERIFY" "$WORK/artifact" "${RELEASE_PUB%%=*}")"

check "a signature checked against a different key is refused" "1" "$(code python3 "$VERIFY" "$WORK/artifact" "$OTHER_PUB")"
check "the refusal says it does not verify against the pinned key" "yes" "$(said 'does NOT verify against the pinned key')"

cp "$WORK/artifact" "$WORK/tampered"
printf 'X' | dd of="$WORK/tampered" bs=1 seek=3 conv=notrunc status=none
cp "$WORK/artifact.sig" "$WORK/tampered.sig"
check "a tampered artifact under a valid signature is refused" "1" "$(code python3 "$VERIFY" "$WORK/tampered" "$RELEASE_PUB")"
check "the tampered refusal is the verification one, not a crash" "yes" "$(said 'does NOT verify')"

head -c 32 "$WORK/artifact.sig" > "$WORK/short.sig"
check "a truncated signature is refused" "1" "$(code python3 "$VERIFY" "$WORK/artifact" "$RELEASE_PUB" "$WORK/short.sig")"

check "a missing signature file does not verify" "1" "$(code python3 "$VERIFY" "$WORK/artifact" "$RELEASE_PUB" "$WORK/no-such.sig")"

# A signature made with another key must not verify against the release key
# even though it is well formed.
env GLYNDOR_RELEASE_ED25519_KEY="$(cat "$WORK/other.seed")" python3 "$SIGN" "$WORK/artifact" "$WORK/other.sig" > /dev/null
check "a well-formed signature from another key is refused" "1" "$(code python3 "$VERIFY" "$WORK/artifact" "$RELEASE_PUB" "$WORK/other.sig")"
check "and it verifies against its own key" "0" "$(code python3 "$VERIFY" "$WORK/artifact" "$OTHER_PUB" "$WORK/other.sig")"

exit "$fail"
