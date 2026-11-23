#!/usr/bin/env bash
#
# Tests that what the documents cite still exists.
#
# docs/security-architecture.md says which file and which function, constant or type
# implements each control, as `internal/auth/mod.rs::verify_command`. A line number goes
# stale without anyone noticing, so none is used, and this test fails on one. For every
# backticked path in docs/*.md, README.md and CONTRIBUTING.md it requires that the file
# exists, and for `path::name` that the name is there: defined with fn, const, static,
# struct, enum, trait, type or mod in a Rust file, defined as a function or present in a
# shell script, present as a word in anything else.
#
# The checker is run first on the real tree and then on small trees that cite a missing file,
# a missing name, a renamed function and a line number, to see each of those fail.

# shellcheck disable=SC2016 # the documents under test are literal text with backticks
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
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

cat > "$WORK/check.py" << 'PY'
import re
import sys
from pathlib import Path

# Files that the documents name and this tree does not hold: the installer of the helmly
# repository, and the SECURITY.md that the organisation's .github repository provides.
EXTERNAL = {"install.sh", "SECURITY.md"}
PATH = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\.(?:rs|sh|py|yml|yaml|toml|json|md)$")
TOKEN = re.compile(r"`([^`\n]+)`")
LINE = re.compile(r"[A-Za-z0-9_./-]+\.(?:rs|sh|py|yml|yaml|toml|json|md):\d+")


def tracked_names(root: Path) -> set:
	return {p.name for p in root.rglob("*") if p.is_file() and ".git" not in p.parts and "target" not in p.parts}


def defined(path: Path, symbol: str) -> bool:
	text = path.read_text(errors="replace")
	last = symbol.split("::")[-1]
	if path.suffix == ".rs":
		if "::" in symbol or not re.fullmatch(r"\w+", symbol):
			return re.search(rf"\b{re.escape(last)}\b", text) is not None
		return re.search(rf"^\s*(?:pub(?:\([a-z]+\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(?:fn|const|static|struct|enum|trait|type|mod|macro_rules!)\s+{re.escape(symbol)}\b", text, re.M) is not None
	if path.suffix == ".sh" and re.fullmatch(r"[A-Za-z_]\w*", symbol):
		return re.search(rf"^\s*(?:function\s+)?{re.escape(symbol)}\s*\(\)", text, re.M) is not None or re.search(rf"\b{re.escape(symbol)}\b", text) is not None
	return symbol in text


def check(root: Path) -> list:
	findings = []
	names = tracked_names(root)
	documents = sorted((root / "docs").glob("*.md")) + [p for p in (root / "README.md", root / "CONTRIBUTING.md") if p.is_file()]
	for doc in documents:
		text = doc.read_text()
		for m in LINE.finditer(text):
			findings.append(f"{doc.name}: `{m.group(0)}` cites a line number; cite the function, constant or type instead")
		for token in TOKEN.findall(text):
			path, _, symbol = token.partition("::")
			if not PATH.match(path) or path in EXTERNAL:
				continue
			target = root / path
			if "/" not in path and not target.is_file():
				if path not in names:
					findings.append(f"{doc.name}: `{token}`: no file named {path} in the tree")
					continue
				if symbol:
					findings.append(f"{doc.name}: `{token}`: a name needs the full path of its file")
				continue
			if not target.is_file():
				findings.append(f"{doc.name}: `{token}`: the file {path} does not exist")
			elif symbol and not defined(target, symbol):
				findings.append(f"{doc.name}: `{token}`: {symbol} is not defined in {path}")
	return findings


if __name__ == "__main__":
	problems = check(Path(sys.argv[1]).resolve())
	for line in problems:
		print(line)
	sys.exit(1 if problems else 0)
PY

# verdict <tree>: "ok" or the first finding
verdict() {
	local out rc=0
	out="$(python3 -I "$WORK/check.py" "$1" 2>&1)" || rc=$?
	if [[ "$rc" -eq 0 ]]; then echo ok; else printf '%s\n' "$out" | head -n 1; fi
}

check "every file and name the documents cite exists in the tree" "ok" "$(verdict "$ROOT")"

# tree <name> <document text>: a tree with one source file and one document
tree() {
	rm -rf "${WORK:?}/$1"
	mkdir -p "$WORK/$1/docs" "$WORK/$1/internal"
	cat > "$WORK/$1/internal/a.rs" << 'RS'
pub const LIMIT: usize = 3;
pub async fn handle_thing() {}
struct Holder;
RS
	printf '#!/usr/bin/env bash\nsetup_thing() {\n  echo hi\n}\nUser=root\n' > "$WORK/$1/setup.sh"
	printf '%s\n' "$2" > "$WORK/$1/docs/d.md"
}

tree a 'The limit is `internal/a.rs::LIMIT` and the handler `internal/a.rs::handle_thing`, in `internal/a.rs::Holder`, `setup.sh::setup_thing` and `setup.sh::User=root`.'
check "a document that cites names that exist passes" "ok" "$(verdict "$WORK/a")"
tree b 'See `internal/missing.rs::handle_thing`.'
check "a cited file that does not exist fails" "d.md: \`internal/missing.rs::handle_thing\`: the file internal/missing.rs does not exist" "$(verdict "$WORK/b")"
tree c 'See `internal/a.rs::handle_other`.'
check "a cited name that is not defined fails" "d.md: \`internal/a.rs::handle_other\`: handle_other is not defined in internal/a.rs" "$(verdict "$WORK/c")"
tree d 'See `internal/a.rs:12`.'
check "a line number fails" "d.md: \`internal/a.rs:12\` cites a line number; cite the function, constant or type instead" "$(verdict "$WORK/d")"
tree e 'See `internal/a.rs::handle_thing`.'
sed -i 's/handle_thing/handle_renamed/' "$WORK/e/internal/a.rs"
check "a function that was renamed fails" "d.md: \`internal/a.rs::handle_thing\`: handle_thing is not defined in internal/a.rs" "$(verdict "$WORK/e")"
tree f 'See `internal/a.rs::LIMIT_OLD`.'
check "a name that only starts like one that exists fails" "d.md: \`internal/a.rs::LIMIT_OLD\`: LIMIT_OLD is not defined in internal/a.rs" "$(verdict "$WORK/f")"
tree g 'See `setup.sh::gone`.'
check "a shell name that is not in the script fails" "d.md: \`setup.sh::gone\`: gone is not defined in setup.sh" "$(verdict "$WORK/g")"
tree h 'See `nothere.rs`.'
check "a bare file name that is nowhere in the tree fails" "d.md: \`nothere.rs\`: no file named nothere.rs in the tree" "$(verdict "$WORK/h")"
tree i 'See `a.rs::LIMIT`.'
check "a name given with only the file name, not its path, fails" "d.md: \`a.rs::LIMIT\`: a name needs the full path of its file" "$(verdict "$WORK/i")"
tree j 'The installer `install.sh` of another repository, and `/etc/glyndor/helmly/x.conf`, and `agent.crt.der` are not this tree'"'"'s files.'
check "a file of another repository, a system path and a data file are not judged" "ok" "$(verdict "$WORK/j")"

exit "$fail"
