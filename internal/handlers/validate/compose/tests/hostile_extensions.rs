//! Runner extensions, the project name and labels that hand a container to a
//! host-side service.

use super::*;

const CASES: &[Hostile] = &[
	(
		"service extension for auto-update",
		"services:\n  web:\n    image: nginx\n    x-podman-autoupdate: registry\n",
		"permits `x-` keys only at the top level",
	),
	(
		"any service extension",
		"services:\n  web:\n    image: nginx\n    x-anything: true\n",
		"permits `x-` keys only at the top level",
	),
	(
		"top-level pod extension",
		"x-podman-pod: true\nservices:\n  web:\n    image: nginx\n",
		"runner extensions",
	),
	(
		"top-level podman-compose extension",
		"x-podman:\n  pod_args: [\"--network=host\"]\nservices:\n  web:\n    image: nginx\n",
		"runner extensions",
	),
	(
		"top-level project name",
		"name: other-project\nservices:\n  web:\n    image: nginx\n",
		"top-level \"name\"",
	),
	(
		"auto-update label, mapping form",
		"services:\n  web:\n    image: nginx\n    labels:\n      io.containers.autoupdate: registry\n",
		"sets the label",
	),
	(
		"auto-update label, list form",
		"services:\n  web:\n    image: nginx\n    labels: [\"io.containers.autoupdate=registry\"]\n",
		"sets the label",
	),
];

#[test]
fn runner_extensions_and_project_name_are_refused() {
	assert_refused(CASES);
}
