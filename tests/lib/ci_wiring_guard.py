"""The guard of the base (wiring-guard.yml) is pinned whole.

It is the one workflow that runs from the base on a pull request and reads the change as
data, so its shape is not left to a comparison of names. Pinned by equality: the events and
their filters, the permissions, no secret, the checkout of the base and nothing else, the
exact lines of the two steps that follow, and that nothing of the change is ever run. Any
other step, any other key of a step, and any key this file does not know is a finding.
"""

from ci_wiring_core import *  # noqa: F403
from ci_wiring_release import GUARD_CHECKOUT_REF

GUARD = "wiring-guard.yml"
GUARD_ENV = {
	"EVENT": "${{ github.event_name }}",
	"PR_NUMBER": "${{ github.event.pull_request.number }}",
	"GROUP_SHA": "${{ github.sha }}",
}
GUARD_FETCH_LINES = (
	'git fetch --no-tags --depth=1 origin "$ref:refs/wiring-guard/change"',
	'mkdir "$RUNNER_TEMP/change"',
	'python3 -I tests/lib/ci_wiring_extract.py refs/wiring-guard/change "$RUNNER_TEMP/change"',
	'pull_request_target)',
	'ref="refs/pull/${PR_NUMBER}/merge" ;;',
	'merge_group)',
	'ref="$GROUP_SHA" ;;',
	'[[ "$PR_NUMBER" =~ ^[0-9]+$ ]] || { echo "::error::the number of the pull request is not a number"; exit 1; }',
	'[[ "$GROUP_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "::error::the commit of the group is not a commit"; exit 1; }',
)


def check_guard(findings: list) -> None:
	path = WORKFLOWS / GUARD
	if not path.is_file():
		return
	doc = load_yaml(path)
	on = doc.get("on", doc.get(True)) or {}
	if set(on) != {"pull_request_target", "merge_group"}:
		findings.append(f"{GUARD}: it must run on pull_request_target and merge_group and on nothing else")
	if on.get("pull_request_target") != {"branches": ["develop", "main"], "types": ["opened", "synchronize", "reopened"]}:
		findings.append(f"{GUARD}: pull_request_target must be limited to the bases develop and main and the types opened, synchronize and reopened")
	if doc.get("permissions") != {"contents": "read"}:
		findings.append(f"{GUARD}: the workflow must hold contents: read and nothing more")
	if set(doc) - {"name", "on", True, "permissions", "concurrency", "jobs"} or "env" in doc or "defaults" in doc:
		findings.append(f"{GUARD}: a key the contract does not know")
	if (doc.get("concurrency") or {}).get("cancel-in-progress") is not False:
		findings.append(f"{GUARD}: a security result is not cancelled by a newer run")
	jobs = doc.get("jobs") or {}
	job = jobs.get("wiring-guard") or {}
	if set(jobs) != {"wiring-guard"} or job.get("name") != "wiring-guard" or set(job) - {"name", "runs-on", "timeout-minutes", "permissions", "steps"}:
		findings.append(f"{GUARD}: one job, wiring-guard, with only name, runs-on, timeout-minutes, permissions and steps")
	if job.get("permissions") != {"contents": "read"} or "environment" in job or "if" in job or "needs" in job:
		findings.append(f"{GUARD}: the job holds contents: read, has no environment, no condition and no dependency")
	steps = job.get("steps") or []
	if len(steps) != 3:
		findings.append(f"{GUARD}: the job has three steps: the checkout of the base, bringing the change in, validating it")
		return
	checkout, fetch, validate = steps
	if (
		not str(checkout.get("uses", "")).startswith("actions/checkout@")
		or checkout.get("with") != {"ref": GUARD_CHECKOUT_REF, "persist-credentials": False}
		or set(checkout) != {"uses", "with"}
	):
		findings.append(f"{GUARD}: the first step must check out the base only (the ref of the group's base, or the tip of the target), with persist-credentials: false")
	lines = [line.strip() for line in str(fetch.get("run", "")).splitlines()]
	if fetch.get("env") != GUARD_ENV or set(fetch) != {"name", "env", "run"}:
		findings.append(f"{GUARD}: the second step must take the event, the number and the commit of the group from exactly their own expressions")
	for needle in GUARD_FETCH_LINES:
		if lines.count(needle) != 1:
			findings.append(f"{GUARD}: the second step must have exactly one line: {needle}")
	words = {word for line in lines for word in line.replace(";", " ").split()}
	if words & {"checkout", "archive", "pip", "source", ".", "bash", "sh", "eval", "exec", "make", "cargo", "npm"} or any(word.startswith("./") for word in words):
		findings.append(f"{GUARD}: the second step must not run, source or check out anything of the change")
	if set(validate) != {"name", "env", "run"} or validate.get("env") != {"CI_WIRING_TREE": "${{ runner.temp }}/change"} or str(validate.get("run", "")).strip() != "python3 -I tests/lib/ci_wiring.py":
		findings.append(f"{GUARD}: the third step must run python3 -I tests/lib/ci_wiring.py of the base, with the tree of the change named in CI_WIRING_TREE and nothing else")
	if any("secrets." in text for text in strings(doc)):  # noqa: F405
		findings.append(f"{GUARD}: no secret may be named here")
