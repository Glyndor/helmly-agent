#!/usr/bin/env bash
#
# The release key is pinned in three places: the installer, the updater script and the
# binary's own updater. A release checks that they agree (the pin check of release.yml),
# which is too late to be the only place: a pull request that changes one of them, in the
# script or in the Rust constant, would reach a tag before anything said the pins differ.
# This test says it on the pull request, and it is selected by the map for a change to any
# of the three files.
#
# It compares slot 0 of the two scripts with `RELEASE_VERIFY_KEY_B64` and with the bytes of
# the first slot of `RELEASE_PUBKEYS`, which is the constant the binary verifies with.

set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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

# judge <dir>: "agree", or the first disagreement, for the files under <dir>
judge() {
	python3 -I - "$1" << 'PY'
import base64, re, sys
root = sys.argv[1]
def read(name):
    return open(f"{root}/{name}", encoding="utf-8").read()
def slot0(text):
    m = re.search(r'^PUB_KEYS_B64 = \[\s*\n(?:\s*#[^\n]*\n)*\s*"([A-Za-z0-9+/=]+)",', text, re.M)
    return m.group(1) if m else ""
rust = read("internal/update/mod.rs")
m = re.search(r'RELEASE_VERIFY_KEY_B64: &str = "([^"]*)"', rust)
b64 = m.group(1) if m else ""
m = re.search(r"RELEASE_PUBKEYS: &\[\[u8; 32\]; 2\] = &\[\s*(?://[^\n]*\n\s*)*\[(.*?)\]", rust, re.S)
bytes_ = bytes(int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", m.group(1))) if m else b""
pins = {"setup-agent.sh": slot0(read("setup-agent.sh")), "update-agent.sh": slot0(read("update-agent.sh")), "RELEASE_VERIFY_KEY_B64": b64}
for name, value in pins.items():
    if not value:
        print(f"{name}: no pin found; the pattern of this test no longer matches the file")
        sys.exit(0)
if len(bytes_) != 32:
    print("RELEASE_PUBKEYS: slot 0 is not 32 bytes, or was not found")
    sys.exit(0)
if len(set(pins.values())) != 1:
    print("the pins disagree: " + ", ".join(f"{k}={v}" for k, v in pins.items()))
    sys.exit(0)
if base64.b64decode(b64) != bytes_:
    print("RELEASE_VERIFY_KEY_B64 and slot 0 of RELEASE_PUBKEYS are different keys")
    sys.exit(0)
print("agree")
PY
}

# copy <name>: the three files in a directory of their own
copy() {
	rm -rf "${WORK:?}/$1"
	mkdir -p "$WORK/$1/internal/update"
	cp "$ROOT/setup-agent.sh" "$ROOT/update-agent.sh" "$WORK/$1/"
	cp "$ROOT/internal/update/mod.rs" "$WORK/$1/internal/update/mod.rs"
}
# edit <name> <file> <python expression on s>: rewrite a file of the copy
edit() {
	python3 -I - "$WORK/$1/$2" "$3" << 'PY'
import sys
path, expr = sys.argv[1], sys.argv[2]
s = open(path, encoding="utf-8").read()
new = eval(expr)
if new == s:
    sys.exit("the edit changed nothing: " + expr)
open(path, "w", encoding="utf-8").write(new)
PY
}

check "the real files agree on the release key" "agree" "$(judge "$ROOT")"

OTHER='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
copy a
edit a setup-agent.sh "s.replace('HFv7vg5FCY7YyKUDbJhaQSfB9SboJGSblJtFbLmLHzM=', '$OTHER', 1)"
check "a key changed in the installer is caught" "the pins disagree" "$(judge "$WORK/a" | cut -c1-17)"

copy b
edit b update-agent.sh "s.replace('HFv7vg5FCY7YyKUDbJhaQSfB9SboJGSblJtFbLmLHzM=', '$OTHER', 1)"
check "a key changed in the updater script is caught" "the pins disagree" "$(judge "$WORK/b" | cut -c1-17)"

copy c
edit c internal/update/mod.rs "s.replace('RELEASE_VERIFY_KEY_B64: &str = \"HFv7vg5FCY7YyKUDbJhaQSfB9SboJGSblJtFbLmLHzM=\"', 'RELEASE_VERIFY_KEY_B64: &str = \"$OTHER\"', 1)"
check "a key changed in the Rust reference is caught" "the pins disagree" "$(judge "$WORK/c" | cut -c1-17)"

copy d
edit d internal/update/mod.rs "s.replace('0x1c, 0x5b,', '0x1d, 0x5b,', 1)"
check "a byte changed in the key the binary verifies with is caught" "RELEASE_VERIFY_KEY_B64 and slot 0 of RELEASE_PUBKEYS are different keys" "$(judge "$WORK/d")"

copy e
edit e setup-agent.sh "s.replace('PUB_KEYS_B64 = [', 'PUB_KEYS = [', 1)"
check "a pattern that no longer finds the installer's pin is caught, not read as agreement" "setup-agent.sh: no pin found" "$(judge "$WORK/e" | cut -d";" -f1)"

copy f
edit f internal/update/mod.rs "s.replace('RELEASE_VERIFY_KEY_B64', 'RELEASE_KEY_B64')"
check "a renamed Rust reference is caught, not read as agreement" "RELEASE_VERIFY_KEY_B64: no pin found" "$(judge "$WORK/f" | cut -d";" -f1)"

copy g
edit g internal/update/mod.rs "s.replace('0x1f, 0x33,', '0x1f,', 1)"
check "a slot with a byte missing is caught" "RELEASE_PUBKEYS: slot 0 is not 32 bytes, or was not found" "$(judge "$WORK/g")"

exit "$fail"
