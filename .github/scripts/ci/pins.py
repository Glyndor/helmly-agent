#!/usr/bin/env python3
"""Check that every action and image the workflows use is pinned to something real.

    pins.py [--base <commit>] [--remote-prefix <url>]     (run at the repository root)

The contract of the wiring tests does not compare the value of a pin, so that the pull
requests of Dependabot, which change a SHA and its version comment together, can pass. This
is the check that gives the value a judge of its own. It reads every `.yml` and `.yaml`
file under `.github/` and, from the loaded YAML (not with a pattern over the lines, so what
GitHub reads and this script does not cannot exist), every `uses`, `image` and `container`.

For each `uses: <owner>/<repo>[/<path>]@<sha> # vMAJOR.MINOR.PATCH`:

- the owner is on the allowed list (`actions`, `github`);
- the reference is a SHA of 40 hex digits and the comment is a strict version;
- the SHA is the commit that the tag of that version points at in that repository, asked
  with `git ls-remote` (the peeled line when the tag is annotated) from a new directory
  outside the repository with no git configuration, so a local setting cannot rewrite the
  URL; when the answer cannot be had, the check fails;
- one repository has one (SHA, version) pair in the whole tree, so the pin of a job with
  privileges cannot move on its own;
- with `--base`, the version is not lower than the one the base commit pins for that
  repository (lowering the version of an action is a decision, not a side effect).

An image (`image:`, `container:`, `docker://`) must be `<repository>@sha256:<64 hex>` with
the repository on the allowed list, which holds none today. A local `./` reference is not
a pin and is not judged. Anything else, an expression included, is a finding.

The base is read in two steps that stay apart: `git cat-file -e <base>^{commit}` says the
commit can be read (it fails when it cannot, and that is a finding), and only then does
`git ls-tree` say whether a file is there. A file the base does not have is absent; one it
has and git cannot show is a finding.

Exit 0 when everything holds, 1 with one finding per line, 2 when the input cannot be read.
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

import yaml

ALLOWED_OWNERS = {"actions", "github"}
ALLOWED_IMAGES: set = set()
REF_KEYS = {"uses", "image", "container"}
ACTION = re.compile(r"^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(/[^@\s]*)?@(\S+)$")
SHA = re.compile(r"^[0-9a-f]{40}$")
VERSION = re.compile(r"^#\s*v(\d+)\.(\d+)\.(\d+)\s*$")
DIGEST = re.compile(r"^([^@\s]+)@sha256:[0-9a-f]{64}$")


class Unreadable(Exception):
	pass


def references(text: str, name: str) -> list:
	"""(line, key, value, comment) of every uses, image and container in a YAML text."""
	try:
		root = yaml.compose(text, Loader=yaml.SafeLoader)
	except yaml.YAMLError as exc:
		raise Unreadable(f"{name}: not valid YAML: {exc}") from exc
	lines = text.splitlines()
	found: list = []
	seen: set = set()

	def walk(node) -> None:
		if node is None or id(node) in seen:
			return
		seen.add(id(node))
		if isinstance(node, yaml.MappingNode):
			for key, value in node.value:
				if isinstance(key, yaml.ScalarNode) and key.value in REF_KEYS:
					if isinstance(value, yaml.ScalarNode):
						line = lines[value.end_mark.line] if value.end_mark.line < len(lines) else ""
						found.append((value.start_mark.line + 1, key.value, value.value, line[value.end_mark.column :].strip()))
					elif not isinstance(value, yaml.MappingNode) or key.value != "container":
						found.append((value.start_mark.line + 1, key.value, None, ""))
				walk(key)
				walk(value)
		elif isinstance(node, yaml.SequenceNode):
			for item in node.value:
				walk(item)

	walk(root)
	return found


def yaml_files(root: Path) -> list:
	base = root / ".github"
	if not base.is_dir():
		return []
	return sorted(p for p in base.rglob("*") if p.suffix in (".yml", ".yaml") and (p.is_file() or p.is_symlink()))


def judge_tree(root: Path) -> tuple:
	"""(findings, {repository: {(sha, version)}}, {(repository, version): [where]})"""
	findings: list = []
	pairs: dict = defaultdict(set)
	where: dict = defaultdict(list)
	for path in yaml_files(root):
		rel = path.relative_to(root).as_posix()
		if path.is_symlink() or not path.is_file():
			findings.append(f"{rel}: is a link; a workflow file must be a regular file")
			continue
		try:
			refs = references(path.read_text(encoding="utf-8"), rel)
		except (Unreadable, UnicodeDecodeError) as exc:
			findings.append(str(exc) if isinstance(exc, Unreadable) else f"{rel}: not UTF-8")
			continue
		for line, key, value, comment in refs:
			here = f"{rel}:{line}"
			if value is None:
				findings.append(f"{here}: `{key}` is not a plain string; this check cannot judge it")
			elif key == "uses" and value.startswith("./"):
				continue
			elif key == "uses" and not value.startswith("docker://"):
				judge_action(here, value, comment, findings, pairs, where)
			else:
				judge_image(here, value.removeprefix("docker://"), findings)
	return findings, pairs, where


def judge_action(here: str, value: str, comment: str, findings: list, pairs: dict, where: dict) -> None:
	m = ACTION.match(value)
	if not m:
		findings.append(f"{here}: `{value}` is not <owner>/<repository>@<sha>")
		return
	owner, repo, _, ref = m.groups()
	if owner.lower() not in ALLOWED_OWNERS:
		findings.append(f"{here}: `{owner}/{repo}` is not from an allowed owner ({', '.join(sorted(ALLOWED_OWNERS))})")
	if not SHA.match(ref):
		findings.append(f"{here}: `{value}` is not pinned to a SHA of 40 hex digits")
		return
	v = VERSION.match(comment)
	if not v:
		findings.append(f"{here}: `{value}` needs a comment of the form `# vMAJOR.MINOR.PATCH` right after it")
		return
	version = tuple(int(x) for x in v.groups())
	pairs[f"{owner}/{repo}".lower()].add((ref, version))
	where[(f"{owner}/{repo}", version)].append((ref, here))


def judge_image(here: str, value: str, findings: list) -> None:
	m = DIGEST.match(value)
	if not m:
		findings.append(f"{here}: image `{value}` is not <repository>@sha256:<64 hex digits>")
	elif m.group(1) not in ALLOWED_IMAGES:
		findings.append(f"{here}: image repository `{m.group(1)}` is not on the allowed list")


def one_pair_each(pairs: dict, where: dict, findings: list) -> None:
	for repo, found in sorted(pairs.items()):
		if len(found) > 1:
			shown = ", ".join(f"{sha[:12]} v{'.'.join(map(str, ver))}" for sha, ver in sorted(found))
			findings.append(f"{repo} is pinned to more than one (SHA, version) in the tree: {shown}")


def remote_commit(prefix: str, repo: str, version: tuple) -> str:
	"""The commit the tag of this version points at, or raise Unreadable."""
	tag = "v" + ".".join(map(str, version))
	with tempfile.TemporaryDirectory(prefix="pins-") as tmp:
		env = {
			"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
			"HOME": tmp,
			"GIT_CONFIG_NOSYSTEM": "1",
			"GIT_CONFIG_GLOBAL": "/dev/null",
			"GIT_TERMINAL_PROMPT": "0",
			"LC_ALL": "C",
		}
		try:
			out = subprocess.run(
				["git", "ls-remote", prefix + repo, f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}"],
				cwd=tmp, env=env, capture_output=True, text=True, timeout=90, check=True,
			).stdout
		except (OSError, subprocess.SubprocessError) as exc:
			raise Unreadable(f"{repo}: cannot ask for the tag {tag}: {exc.__class__.__name__}") from exc
	commits = {}
	for line in out.splitlines():
		sha, _, ref = line.partition("\t")
		commits[ref.strip()] = sha.strip()
	peeled = commits.get(f"refs/tags/{tag}^{{}}") or commits.get(f"refs/tags/{tag}")
	if not peeled or not SHA.match(peeled):
		raise Unreadable(f"{repo}: the tag {tag} does not exist")
	return peeled


def verify_remote(prefix: str, where: dict, findings: list) -> None:
	for (repo, version), uses in sorted(where.items()):
		try:
			commit = remote_commit(prefix, repo, version)
		except Unreadable as exc:
			findings.append(str(exc))
			continue
		for sha, here in uses:
			if sha != commit:
				findings.append(f"{here}: {sha[:12]} is not the commit of {repo} v{'.'.join(map(str, version))} ({commit[:12]})")


def git(*args: str) -> str:
	return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout


def base_versions(base: str) -> dict:
	"""{repository: highest version} pinned at the base commit."""
	try:
		git("cat-file", "-e", f"{base}^{{commit}}")
	except (OSError, subprocess.CalledProcessError) as exc:
		raise Unreadable(f"the base commit {base} cannot be read; no version can be compared") from exc
	try:
		listing = git("ls-tree", "-r", "--name-only", "-z", base, "--", ".github")
	except (OSError, subprocess.CalledProcessError) as exc:
		raise Unreadable("the base commit's .github cannot be listed") from exc
	versions: dict = {}
	for name in sorted(p for p in listing.split("\0") if p.endswith((".yml", ".yaml"))):
		try:
			text = git("show", f"{base}:{name}")
		except (OSError, subprocess.CalledProcessError) as exc:
			raise Unreadable(f"{name} is in the base commit and cannot be read") from exc
		for _, key, value, comment in references(text, name):
			m = ACTION.match(value or "") if key == "uses" else None
			v = VERSION.match(comment)
			if m and v and not (value or "").startswith(("./", "docker://")):
				repo = f"{m.group(1)}/{m.group(2)}".lower()
				version = tuple(int(x) for x in v.groups())
				versions[repo] = max(versions.get(repo, version), version)
	return versions


def not_lower(pairs: dict, base: dict, findings: list) -> None:
	for repo, found in sorted(pairs.items()):
		for _, version in found:
			if repo in base and version < base[repo]:
				findings.append(f"{repo} goes from v{'.'.join(map(str, base[repo]))} to v{'.'.join(map(str, version))}; lowering the version of an action needs an explicit decision")


def main(argv: list) -> int:
	parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument("--base", help="the commit of the base branch, to compare versions with")
	parser.add_argument("--remote-prefix", default="https://github.com/", help="where the repositories are asked for their tags")
	args = parser.parse_args(argv)
	root = Path.cwd()
	findings, pairs, where = judge_tree(root)
	one_pair_each(pairs, where, findings)
	try:
		if args.base:
			not_lower(pairs, base_versions(args.base), findings)
	except Unreadable as exc:
		findings.append(str(exc))
	verify_remote(args.remote_prefix, where, findings)
	for finding in findings:
		print(f"::error::{finding}")
	if not findings:
		print(f"pins: {sum(len(v) for v in where.values())} references, every one pinned to the commit of its tag")
	return 1 if findings else 0


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
