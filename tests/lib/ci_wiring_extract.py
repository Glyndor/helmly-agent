#!/usr/bin/env python3
"""Write the `.github` tree of a commit into a directory as plain files, and nothing else.

    ci_wiring_extract.py <commit-ish> <directory>      (run in the repository that holds it)

The validator that the base holds reads the workflows of a pull request as data, so the
files must come out the way they are in the tree: `git archive` would apply the
attributes of the tree it archives (`export-ignore` drops a file from the copy that is
read while it stays in the repository, `export-subst` rewrites its text). This reads each
entry with `git ls-tree` and `git cat-file blob`, which apply no attribute and run no filter
or hook, and writes only regular files under the directory. A link, a submodule, a path that
leaves the directory, a name that is not valid UTF-8, an entry that appears twice, or a file
over the size limit makes it fail, and a failure leaves no
tree to validate.

Exit 0, or 1 with one finding per line, or 2 when the commit cannot be read.
"""

import subprocess
import sys
from pathlib import Path

LIMIT = 2 * 1024 * 1024
REGULAR = {"100644", "100755"}


def git(*args: str) -> bytes:
	return subprocess.run(["git", *args], capture_output=True, check=True).stdout


def main(argv: list) -> int:
	if len(argv) != 2:
		print("usage: ci_wiring_extract.py <commit-ish> <directory>", file=sys.stderr)
		return 2
	ref, dest = argv[0], Path(argv[1])
	try:
		listing = git("ls-tree", "-r", "-z", "--full-tree", ref, "--", ".github")
	except (OSError, subprocess.CalledProcessError):
		print(f"::error::cannot read {ref}", file=sys.stderr)
		return 2
	if not dest.is_dir() or any(dest.iterdir()):
		print("::error::the directory must exist and be empty", file=sys.stderr)
		return 2
	root = dest.resolve()
	findings = []
	for entry in filter(None, listing.split(b"\0")):
		meta, _, raw = entry.partition(b"\t")
		mode, kind, oid = meta.decode().split()
		try:
			name = raw.decode("utf-8")
		except UnicodeDecodeError:
			# Replacing the bytes that do not decode would let two different paths collide.
			findings.append(f"{raw.decode('utf-8', errors='backslashreplace')}: the name is not valid UTF-8")
			continue
		if mode not in REGULAR or kind != "blob":
			findings.append(f"{name}: is not a regular file (mode {mode}); a link or a submodule under .github is refused")
			continue
		target = (root / name).resolve()
		if root not in target.parents:
			findings.append(f"{name}: leaves the directory")
			continue
		size = int(git("cat-file", "-s", oid).decode())
		if size > LIMIT:
			findings.append(f"{name}: is {size} bytes, over the limit of {LIMIT}")
			continue
		target.parent.mkdir(parents=True, exist_ok=True)
		try:
			# Exclusive: an entry that is written twice is an error, not the last one winning.
			with open(target, "xb") as out:
				out.write(git("cat-file", "blob", oid))
		except FileExistsError:
			findings.append(f"{name}: appears twice in the tree")
			continue
		target.chmod(0o644)
	for finding in findings:
		print(f"::error::{finding}")
	return 1 if findings else 0


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
