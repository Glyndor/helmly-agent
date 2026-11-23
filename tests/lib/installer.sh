#!/usr/bin/env bash
# Helpers for the tests of the blocks of setup-agent.sh and update-agent.sh that act on the host.
#
# Both installers are linear scripts that must run as root and change the machine within
# seventy lines, so none of them can be sourced or run as a whole. A test takes the one
# block it is about, by the text that opens and closes it (never by line number), points
# the absolute paths of the block into a scratch directory, puts programs that only write
# down how they were called ahead of the real ones on the PATH, and runs it in a fresh
# shell. A block or a function that is not found is a failure of the test, so a change that
# moves or renames one is seen rather than skipped.
#
# Source it from a test; it sets ROOT, SETUP, UPDATE, WORK, `fail` and an exit trap.

# shellcheck disable=SC2034,SC2329,SC2317 # variables and functions are read and called by the sourcing tests
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SETUP="$ROOT/setup-agent.sh"
UPDATE="$ROOT/update-agent.sh"
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

# block <file> <opening regex> <closing regex>: the lines from the first one that matches
# the opening to the first one after it that matches the closing, both included.
block() {
	local out
	out="$(awk -v open="$2" -v close_="$3" '
		!started && $0 ~ open { started = 1 }
		started { print }
		started && $0 ~ close_ { closed = 1; exit }
		END { if (!started || !closed) exit 1 }
	' "$1")" || {
		echo "FAIL could not find the block /$2/ .. /$3/ in $1; the markers moved" >&2
		exit 1
	}
	printf '%s\n' "$out"
}

# function_of <file> <name>: a function by its name, from `name() {` to the first `}` in column 0.
function_of() {
	local out
	out="$(sed -n "/^$2() {/,/^}/p" "$1")"
	[[ -n "$out" ]] || {
		echo "FAIL function $2 not found in $1" >&2
		exit 1
	}
	printf '%s\n' "$out"
}

# sandbox <name>: a scratch tree for one case, in $T, with its own programs in $T/fakes.
sandbox() {
	T="$WORK/$1"
	rm -rf "$T"
	mkdir -p "$T/fakes" "$T/etc" "$T/tmp"
	: > "$T/calls"
}

# fake <program> [body]: a program that writes down its name and arguments in $T/calls and
# then runs `body`, which sees the arguments as $@ and may `exit` with a status.
fake() {
	{
		printf '#!/usr/bin/env bash\n'
		# shellcheck disable=SC2016 # this is the text of the program, expanded when it runs
		printf 'printf "%%s" "$(basename "$0")" >> "%s/calls"; printf " %%s" "$@" >> "%s/calls"; echo >> "%s/calls"\n' "$T" "$T" "$T"
		printf '%s\n' "${2:-:}"
	} > "$T/fakes/$1"
	chmod +x "$T/fakes/$1"
}

# calls <program>: how many times it ran.
calls() { grep -c "^$1\( \|\$\)" "$T/calls" || true; }

# run_block <script text> [VAR=value ...]: run the text under `set -euo pipefail` in a fresh
# shell whose PATH starts with the fakes, after the given variables and the logging functions
# of the installers. The absolute /etc/ and /tmp/ paths of the text go to $T/etc/ and $T/tmp/. Status in $RC,
# output in $T/out.
run_block() {
	local text="$1"
	shift
	{
		printf 'set -euo pipefail\n'
		printf 'log_info() { echo "[INFO] $*"; }; log_ok() { echo "[OK] $*"; }; log_warn() { echo "[WARN] $*"; }\n'
		printf 'log_error() { echo "[ERROR] $*" >&2; }; log_section() { echo "== $*"; }\n'
		printf '%s\n' "$text" | sed "s#/etc/#@ETC@/#g; s#/tmp/#@TMP@/#g; s#@ETC@#$T/etc#g; s#@TMP@#$T/tmp#g"
		printf 'echo REACHED_END\n'
	} > "$T/script.sh"
	RC=0
	(cd "$T" && env -i PATH="$T/fakes:/usr/bin:/bin" HOME="$T" T="$T" "$@" bash "$T/script.sh") > "$T/out" 2>&1 || RC=$?
}

reached() { if grep -q '^REACHED_END$' "$T/out"; then echo yes; else echo no; fi; }
mode_of() { stat -c '%a' "$1"; }
