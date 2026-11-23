"""The guard of the base (wiring-guard.yml) is pinned whole, by equality.

It is the one workflow that runs from the base on a pull request and reads the change as
data, so its shape is not left to a comparison of names or to lists of lines and words.
Pinned by equality: the whole `on` block, the permissions, `runs-on`, the concurrency
group, the name expression, the checkout of the base and nothing else, and the full text
of each `run`. No `run` holds an expression, no expression names a secret, and the guard
is missing is a finding. No other workflow may be triggered by `pull_request_target`
(it would run with the token of the base on a change) or emit the name of this check.
"""

import re

from ci_wiring_core import *  # noqa: F403

GUARD = "wiring-guard.yml"
GUARD_ON = {"pull_request_target": {"branches": ["develop", "main"], "types": ["opened", "synchronize", "reopened"]}}
GUARD_CONCURRENCY = {"group": "wiring-guard-${{ github.event.pull_request.number }}", "cancel-in-progress": False}
GUARD_ENV = {
	"EVENT": "${{ github.event_name }}",
	"PR_NUMBER": "${{ github.event.pull_request.number }}",
	"HEAD_SHA": "${{ github.event.pull_request.head.sha }}",
}
GUARD_FETCH_RUN = """\
set -euo pipefail
[ "$EVENT" = pull_request_target ] || { echo "::error::an event this guard does not judge: $EVENT"; exit 1; }
[[ "$PR_NUMBER" =~ ^[0-9]+$ ]] || { echo "::error::the number of the pull request is not a number"; exit 1; }
[[ "$HEAD_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "::error::the head of the pull request is not a commit"; exit 1; }
git fetch --no-tags --depth=1 origin "refs/pull/${PR_NUMBER}/merge:refs/wiring-guard/change"
# GitHub makes the merge ref in the background, so it can be behind the head.
# Its second parent is the head it merged, and it has to be the head of this event.
merged_head="$(git cat-file -p refs/wiring-guard/change | awk '/^$/ {exit} /^parent / {print $2}' | sed -n 2p)"
[ "$merged_head" = "$HEAD_SHA" ] || { echo "::error::the merge ref holds ${merged_head:-no head}, not the head of the pull request ($HEAD_SHA); run it again once GitHub has made it"; exit 1; }
mkdir "$RUNNER_TEMP/change"
python3 -I tests/lib/ci_wiring_extract.py refs/wiring-guard/change "$RUNNER_TEMP/change"
"""
GUARD_VALIDATE_RUN = "python3 -I tests/lib/ci_wiring.py"
GUARD_NAME_PREFIX = "wiring-guard"
EXPRESSION = re.compile(r"\$\{\{.*?\}\}", re.S)
SECRET_WORD = re.compile(r"\bsecrets\b")


def check_guard(findings: list) -> None:
	path = WORKFLOWS / GUARD
	others = [p for p in workflow_files() if p.name != GUARD]
	for other in others:
		doc = load_yaml(other)
		if "pull_request_target" in triggers(doc):
			findings.append(f"{other.name}: a workflow triggered by pull_request_target runs with the token of the base on a change; only {GUARD} may be")
		for job_id, job in (doc.get("jobs") or {}).items():
			if str(job.get("name", job_id)).lower().startswith(GUARD_NAME_PREFIX):
				findings.append(f"{other.name}: job {job_id!r} carries the name of the guard's check; only {GUARD} may emit it")
	if not path.is_file():
		findings.append(f"{GUARD} is missing: the guard of the base that judges a change by the validator the change cannot touch is part of the contract")
		return
	doc = load_yaml(path)
	if (doc.get("on", doc.get(True))) != GUARD_ON:
		findings.append(f"{GUARD}: the `on` block must be exactly pull_request_target for the bases develop and main on opened, synchronize and reopened")
	if doc.get("permissions") != {"contents": "read"}:
		findings.append(f"{GUARD}: the workflow must hold contents: read and nothing more")
	if set(doc) - {"name", "on", True, "permissions", "concurrency", "jobs"} or doc.get("name") != "wiring-guard":
		findings.append(f"{GUARD}: a key or a name the contract does not know")
	if doc.get("concurrency") != GUARD_CONCURRENCY:
		findings.append(f"{GUARD}: the concurrency must be the group of the pull request, and never cancel a run in progress")
	jobs = doc.get("jobs") or {}
	job = jobs.get("wiring-guard") or {}
	if set(jobs) != {"wiring-guard"} or set(job) != {"name", "runs-on", "timeout-minutes", "permissions", "steps"}:
		findings.append(f"{GUARD}: one job, wiring-guard, with only name, runs-on, timeout-minutes, permissions and steps")
	if job.get("runs-on") != "ubuntu-latest" or job.get("timeout-minutes") != 5:
		findings.append(f"{GUARD}: the job runs on ubuntu-latest, for at most 5 minutes")
	if job.get("permissions") != {"contents": "read"}:
		findings.append(f"{GUARD}: the job holds contents: read, and no environment, condition or dependency")
	if job.get("name") != GUARD_NAME:
		findings.append(f"{GUARD}: the check is named by the base: wiring-guard for develop, wiring-guard (main) for main")
	steps = job.get("steps") or []
	if len(steps) != 3:
		findings.append(f"{GUARD}: the job has three steps: the checkout of the base, bringing the change in, validating it")
		return
	checkout, fetch, validate = steps
	if (
		not re.fullmatch(r"actions/checkout@[0-9a-f]{40}", str(checkout.get("uses", "")))
		or checkout.get("with") != {"persist-credentials": False}
		or set(checkout) != {"uses", "with"}
	):
		findings.append(f"{GUARD}: the first step must check out the base only (no ref), with persist-credentials: false")
	if set(fetch) != {"name", "env", "run"} or fetch.get("env") != GUARD_ENV:
		findings.append(f"{GUARD}: the second step must take the event, the number and the head from exactly their own expressions")
	if str(fetch.get("run", "")).strip() != GUARD_FETCH_RUN.strip():
		findings.append(f"{GUARD}: the second step must be, word for word, the one that fetches the merge ref, checks its head and extracts the tree")
	if set(validate) != {"name", "env", "run"} or validate.get("env") != {"CI_WIRING_TREE": "${{ runner.temp }}/change"} or str(validate.get("run", "")).strip() != GUARD_VALIDATE_RUN:
		findings.append(f"{GUARD}: the third step must run python3 -I tests/lib/ci_wiring.py of the base, with the tree of the change named in CI_WIRING_TREE and nothing else")
	for step in steps:
		if "${{" in str(step.get("run", "")):
			findings.append(f"{GUARD}: no run may hold an expression; a value enters through env")
	for text in strings(doc):  # noqa: F405
		if any(SECRET_WORD.search(expression) for expression in EXPRESSION.findall(text)):
			findings.append(f"{GUARD}: no secret may be named here")
