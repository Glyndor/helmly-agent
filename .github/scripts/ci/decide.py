#!/usr/bin/env python3
"""Decide which CI suites a change set has anything to check in.

Reads the paths a change touched (NUL- or newline-separated) on stdin and the
map in `.github/ci-map.json`, and prints one `<suite>=true|false` line per suite,
ready to append to `$GITHUB_OUTPUT`.

    decide.py --map .github/ci-map.json < changed-paths
    decide.py --map .github/ci-map.json --audit-map < tracked-paths

The map names the suites (`suites`), the paths whose change reruns every suite
(`everything`) and the paths that no suite looks at (`no-suite`). Patterns use
`*` for anything but `/`, `**` for anything, `?` for one character, and a
trailing `/**` for the whole subtree.

The decision FAILS OPEN. A path the map does not know, an empty change set, an
unreadable map or any error answers "run everything": a wrong skip lets a merge
pass without anything having looked at it, and a wrong run only costs minutes.
The exit status is 0 for a decision, 2 when the input could not be used, and
the workflow treats 2 as "run everything" too.

`--audit-map` is the other direction. Given every tracked path it fails when a
tracked path is claimed by nothing (a file no suite would ever run for), when a
`no-suite` path is also claimed by a suite (a contradiction), and when a pattern
matches no tracked path at all (a suite that would run for a change that cannot
happen). Exit 1 lists each finding.
"""

import argparse
import json
import re
import sys

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_UNUSABLE = 2


def glob_to_regex(pattern: str) -> "re.Pattern[str]":
	"""Translate one map pattern to an anchored regular expression."""
	if not pattern or pattern.startswith("/") or pattern.startswith("./") or ".." in pattern.split("/"):
		raise ValueError(f"pattern {pattern!r} must be a relative path pattern")
	out = []
	i = 0
	while i < len(pattern):
		c = pattern[i]
		if pattern.startswith("**/", i):
			out.append("(?:.*/)?")
			i += 3
		elif pattern.startswith("**", i):
			out.append(".*")
			i += 2
		elif c == "*":
			out.append("[^/]*")
			i += 1
		elif c == "?":
			out.append("[^/]")
			i += 1
		else:
			out.append(re.escape(c))
			i += 1
	return re.compile("^" + "".join(out) + "$")


class CiMap:
	"""The parsed, validated map."""

	def __init__(self, raw: object) -> None:
		if not isinstance(raw, dict):
			raise ValueError("the map must be a JSON object")
		extra = set(raw) - {"suites", "everything", "no-suite"}
		if extra:
			raise ValueError(f"unknown keys in the map: {sorted(extra)}")
		suites = raw.get("suites")
		if not isinstance(suites, dict) or not suites:
			raise ValueError("'suites' must be a non-empty object")
		self.patterns: dict = {}
		for name, patterns in suites.items():
			if not re.fullmatch(r"[a-z][a-z0-9-]*", name):
				raise ValueError(f"suite name {name!r} is not a lower-case identifier")
			self.patterns[name] = self._compile_list(name, patterns)
		self.everything = self._compile_list("everything", raw.get("everything", []))
		self.no_suite = self._compile_list("no-suite", raw.get("no-suite", []))

	@staticmethod
	def _compile_list(what: str, patterns: object) -> list:
		if not isinstance(patterns, list) or not all(isinstance(p, str) for p in patterns):
			raise ValueError(f"{what!r} must be a list of strings")
		if what != "everything" and what != "no-suite" and not patterns:
			raise ValueError(f"suite {what!r} has no patterns")
		return [(p, glob_to_regex(p)) for p in patterns]

	@staticmethod
	def _matches(compiled: list, path: str) -> bool:
		return any(rx.match(path) for _, rx in compiled)

	def suites_for(self, path: str) -> set:
		return {name for name, compiled in self.patterns.items() if self._matches(compiled, path)}

	def runs_everything(self, path: str) -> bool:
		return self._matches(self.everything, path)

	def is_no_suite(self, path: str) -> bool:
		return self._matches(self.no_suite, path)

	def names(self) -> list:
		return list(self.patterns)


def read_paths(raw: bytes) -> list:
	"""Split stdin into paths. NUL separates when present, a newline otherwise."""
	sep = b"\0" if b"\0" in raw else b"\n"
	paths = [p.decode("utf-8", "strict") for p in raw.split(sep) if p]
	for p in paths:
		if "\n" in p or "\r" in p:
			raise ValueError(f"a path with a line break cannot be classified: {p!r}")
	return paths


def decide(paths: list, cmap: CiMap) -> tuple:
	"""Return (selected suite names, reason). Fails open on anything unknown."""
	if not paths:
		return set(cmap.names()), "no changed path was given"
	selected: set = set()
	for path in paths:
		if cmap.runs_everything(path):
			return set(cmap.names()), f"{path} reruns every suite"
		matched = cmap.suites_for(path)
		if matched:
			selected |= matched
		elif not cmap.is_no_suite(path):
			return set(cmap.names()), f"{path} is in no suite and is not declared as having none"
	return selected, f"{len(paths)} changed path(s)"


def audit_map(tracked: list, cmap: CiMap) -> list:
	"""Findings for the other direction: the map against the tracked tree."""
	findings = []
	for path in tracked:
		suites = cmap.suites_for(path)
		everything = cmap.runs_everything(path)
		none = cmap.is_no_suite(path)
		if not suites and not everything and not none:
			findings.append(f"unclaimed: {path} is tracked and no suite, 'everything' or 'no-suite' pattern covers it")
		if none and (suites or everything):
			where = sorted(suites) + (["everything"] if everything else [])
			findings.append(f"contradiction: {path} is declared 'no-suite' and also claimed by {where}")
	groups = [(f"suites.{n}", cmap.patterns[n]) for n in cmap.names()]
	groups += [("everything", cmap.everything), ("no-suite", cmap.no_suite)]
	for label, compiled in groups:
		for pattern, rx in compiled:
			if not any(rx.match(p) for p in tracked):
				findings.append(f"dead pattern: {label} has {pattern!r}, which matches no tracked path")
	return findings


def main(argv: list) -> int:
	parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument("--map", required=True, help="path of ci-map.json")
	parser.add_argument("--audit-map", action="store_true", help="check the map against the tracked paths on stdin")
	args = parser.parse_args(argv)
	try:
		with open(args.map, encoding="utf-8") as fh:
			cmap = CiMap(json.load(fh))
		paths = read_paths(sys.stdin.buffer.read())
	except (OSError, ValueError) as exc:
		print(f"decide: cannot use the input: {exc}", file=sys.stderr)
		return EXIT_UNUSABLE

	if args.audit_map:
		findings = audit_map(paths, cmap)
		for finding in findings:
			print(f"::error::{finding}")
		if findings:
			return EXIT_FINDINGS
		print(f"ci-map: {len(paths)} tracked paths, every one claimed, no dead pattern")
		return EXIT_OK

	selected, reason = decide(paths, cmap)
	print(f"decide: {reason}; running {sorted(selected) or 'nothing'}", file=sys.stderr)
	for name in cmap.names():
		print(f"{name}={'true' if name in selected else 'false'}")
	return EXIT_OK


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
