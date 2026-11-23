#!/usr/bin/env bash
#
# Tests for .github/scripts/release/sign-artifacts.sh, the script the signing job runs
# on the artifacts the build jobs uploaded and on the two installer scripts.
#
# The directories it is given are data from other jobs and from the checkout, and the
# script holds the release key, so the cases are about what it refuses BEFORE it reads
# the key or writes anything: a name more or less than expected, a link, a folder where
# a file should be, a relative path, an output directory that already exists. Two more
# are about what it runs: the signer must run isolated, so a module planted in the data
# or in the working directory is never imported. One round trip with the real signer
# and the real verifier shows that what is signed verifies.

set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/.github/scripts/release/sign-artifacts.sh"
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

# A stand-in signer that records the interpreter's import path and whether it found a
# module called cryptography, so the isolation can be asserted without the real library.
STUB='import importlib.util, json, sys
spec = importlib.util.find_spec("cryptography")
open(sys.argv[1] + ".sig", "w").write(json.dumps({"path": sys.path, "cryptography": spec.origin if spec else None}))
'

# fixture <name> [stub|real]: a workspace, an artifacts directory and an installers directory
fixture() {
	local d="$WORK/$1"
	rm -rf "$d"
	mkdir -p "$d/work/.github/scripts" "$d/artifacts/x86_64" "$d/artifacts/arm64" "$d/installers"
	if [[ "${2:-stub}" == real ]]; then
		cp "$ROOT/.github/scripts/sign.py" "$d/work/.github/scripts/sign.py"
	else
		printf '%s' "$STUB" > "$d/work/.github/scripts/sign.py"
	fi
	for arch in x86_64 arm64; do echo "binary $arch" > "$d/artifacts/$arch/helmly-agent-linux-$arch"; done
	echo "#!/bin/sh" > "$d/installers/setup-agent.sh"
	echo "#!/bin/sh" > "$d/installers/update-agent.sh"
}
# run <name> [key]: prints the exit code; the output is in $WORK/<name>.out
run() {
	local d="$WORK/$1" rc=0 key="${2-AAAA}"
	rm -rf "$d/out"
	(cd "$d" && env -u GLYNDOR_RELEASE_ED25519_KEY ${key:+GLYNDOR_RELEASE_ED25519_KEY="$key"} GITHUB_WORKSPACE="$d/work" \
		bash "$SCRIPT" "$d/artifacts" "$d/installers" "$d/out" > "$WORK/$1.out" 2>&1) || rc=$?
	echo "$rc"
}
signed() { # signed <name>: the names signed, or "none" when nothing was written
	if [[ -d "$WORK/$1/out" ]]; then find "$WORK/$1/out" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//'; else echo none; fi
}

fixture a
check "the expected files are signed" "0" "$(run a)"
check "the output holds the four assets, their signatures, the sums and its signature" \
	"SHA256SUMS SHA256SUMS.sig helmly-agent-linux-arm64 helmly-agent-linux-arm64.sig helmly-agent-linux-x86_64 helmly-agent-linux-x86_64.sig setup-agent.sh setup-agent.sh.sig update-agent.sh update-agent.sh.sig" "$(signed a)"
check "the sums list the four assets" "4" "$(wc -l < "$WORK/a/out/SHA256SUMS" | tr -d ' ')"

for extra in "artifacts/x86_64/notes.txt" "artifacts/arm64/.hidden" "artifacts/stray" "installers/extra.sh"; do
	fixture b
	echo x > "$WORK/b/$extra"
	check "a name more ($extra) is refused and nothing is written" "1 none" "$(run b) $(signed b)"
done

fixture c
rm "$WORK/c/artifacts/arm64/helmly-agent-linux-arm64"
check "a missing artifact is refused" "1 none" "$(run c) $(signed c)"

fixture d
rm "$WORK/d/installers/update-agent.sh"
check "a missing installer is refused" "1 none" "$(run d) $(signed d)"

fixture e
echo target > "$WORK/target"
rm "$WORK/e/artifacts/x86_64/helmly-agent-linux-x86_64"
ln -s "$WORK/target" "$WORK/e/artifacts/x86_64/helmly-agent-linux-x86_64"
check "an artifact that is a link is refused" "1 none" "$(run e) $(signed e)"
grep -q 'is not a regular file' "$WORK/e.out" && r=said || r=silent
check "and the refusal says why" "said" "$r"

fixture f
rm "$WORK/f/installers/setup-agent.sh"
ln -s "$WORK/target" "$WORK/f/installers/setup-agent.sh"
check "an installer that is a link is refused" "1 none" "$(run f) $(signed f)"

fixture g
rm -rf "$WORK/g/artifacts/arm64"
ln -s "$WORK/g/installers" "$WORK/g/artifacts/arm64"
check "an architecture folder that is a link is refused" "1 none" "$(run g) $(signed g)"

fixture g2
mkdir "$WORK/g2/elsewhere"
echo "binary arm64" > "$WORK/g2/elsewhere/helmly-agent-linux-arm64"
rm -rf "$WORK/g2/artifacts/arm64"
ln -s "$WORK/g2/elsewhere" "$WORK/g2/artifacts/arm64"
check "an architecture folder that is a link to a folder with the right file is refused" "1 none" "$(run g2) $(signed g2)"

fixture g3
mv "$WORK/g3/artifacts" "$WORK/g3/real-artifacts"
ln -s "$WORK/g3/real-artifacts" "$WORK/g3/artifacts"
check "an artifacts directory that is a link is refused" "1 none" "$(run g3) $(signed g3)"

fixture h
rm "$WORK/h/artifacts/x86_64/helmly-agent-linux-x86_64"
mkdir "$WORK/h/artifacts/x86_64/helmly-agent-linux-x86_64"
check "a folder in place of a file is refused" "1 none" "$(run h) $(signed h)"

fixture i
check "a missing key is refused after the data is checked and before anything is written" "1 none" "$(run i "") $(signed i)"
grep -q 'the signing key is not set' "$WORK/i.out" && r=said || r=silent
check "and the refusal names the key" "said" "$r"

fixture j
(cd "$WORK/j" && env GLYNDOR_RELEASE_ED25519_KEY=AAAA GITHUB_WORKSPACE="$WORK/j/work" bash "$SCRIPT" artifacts installers out > "$WORK/j.out" 2>&1) && rc=0 || rc=$?
check "a relative directory is refused" "1" "$rc"

fixture k
mkdir "$WORK/k/out"
check "an output directory that already exists is refused" "1" "$(cd "$WORK/k" && env GLYNDOR_RELEASE_ED25519_KEY=AAAA GITHUB_WORKSPACE="$WORK/k/work" bash "$SCRIPT" "$WORK/k/artifacts" "$WORK/k/installers" "$WORK/k/out" > "$WORK/k.out" 2>&1; echo $?)"

# --- the signer runs isolated -----------------------------------------------------------
fixture l
printf 'raise SystemExit("the planted module was imported")\n' > "$WORK/l/work/cryptography.py"
printf 'raise SystemExit("the planted module was imported")\n' > "$WORK/l/cryptography.py"
check "a module planted in the workspace and in the working directory does not stop the signing" "0" "$(run l)"
seen="$(python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); print(("" in d["path"]), any(sys.argv[2] in p for p in d["path"]), d["cryptography"] is None or sys.argv[2] not in d["cryptography"])' "$WORK/l/out/helmly-agent-linux-x86_64.sig" "$WORK/l")"
check "the working directory and the workspace are not on its import path, and the planted module was not found" "False False True" "$seen"

fixture m
echo 'raise SystemExit("planted")' > "$WORK/m/artifacts/cryptography.py"
check "a file planted among the artifacts is refused, not imported" "1 none" "$(run m) $(signed m)"

# --- what comes out is exactly the files of a release ---------------------------------------
fixture o
printf 'import os, sys\nopen(sys.argv[1] + ".sig", "w").write("sig")\nopen(os.path.join(os.path.dirname(sys.argv[1]), "extra"), "w").write("x")\n' > "$WORK/o/work/.github/scripts/sign.py"
check "a signer that leaves a file more in the output is refused" "1" "$(run o)"
grep -q 'does not hold exactly the files of a release' "$WORK/o.out" && r=said || r=silent
check "and the refusal says why" "said" "$r"
fixture p
printf 'import os, sys\nif not sys.argv[1].endswith("SHA256SUMS"):\n    open(sys.argv[1] + ".sig", "w").write("sig")\n' > "$WORK/p/work/.github/scripts/sign.py"
check "a signer that leaves a signature out is refused" "1" "$(run p)"

# --- a round trip with the real signer and the real verifier ------------------------------
fixture n real
KEYS="$(python3 -I - << 'PY'
import base64, os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
seed = os.urandom(32)
pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
print(base64.b64encode(seed).decode(), base64.b64encode(pub).decode())
PY
)"
SEED="${KEYS% *}"
PUB="${KEYS#* }"
check "the real signer signs the release" "0" "$(run n "$SEED")"
ok=yes
for f in helmly-agent-linux-x86_64 helmly-agent-linux-arm64 setup-agent.sh update-agent.sh SHA256SUMS; do
	python3 -I "$ROOT/.github/scripts/verify-release.py" "$WORK/n/out/$f" "$PUB" > /dev/null 2>&1 || ok=no
done
check "every signature verifies against the public key of the throwaway key" "yes" "$ok"
check "the sums are the sums of the files" "0" "$(cd "$WORK/n/out" && sha256sum -c SHA256SUMS > /dev/null 2>&1; echo $?)"
python3 -I "$ROOT/.github/scripts/verify-release.py" "$WORK/n/out/setup-agent.sh" "$PUB" > /dev/null 2>&1 && ok=yes || ok=no
echo "tampered" >> "$WORK/n/out/setup-agent.sh"
python3 -I "$ROOT/.github/scripts/verify-release.py" "$WORK/n/out/setup-agent.sh" "$PUB" > /dev/null 2>&1 && t=accepted || t=refused
check "an asset changed after signing no longer verifies" "refused" "$t"

exit "$fail"
