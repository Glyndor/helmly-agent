//! Bind sources outside the project directory, in the short and the long form,
//! and named volumes that are host binds in disguise. The link cases, which
//! need a real directory, are in `canonical`.

use super::*;

const OUTSIDE: &str = "outside the tenant root";
const DOTDOT: &str = "contains `..`";

const CASES: &[Hostile] = &[
	("host root", "services:\n  web:\n    image: nginx\n    volumes: [\"/:/host\"]\n", OUTSIDE),
	(
		"host root, long form",
		"services:\n  web:\n    image: nginx\n    volumes:\n      - type: bind\n        source: /etc/passwd\n        target: /in/container\n",
		OUTSIDE,
	),
	(
		"the directory the handler used to pass",
		"services:\n  web:\n    image: nginx\n    volumes: [\"/var/lib/glyndor/helmly/tenants/t1/p1/x:/x\"]\n",
		OUTSIDE,
	),
	(
		"another project of the same tenant",
		"services:\n  web:\n    image: nginx\n    volumes: [\"/var/lib/glyndor/helmly/projects/t1/p2:/x\"]\n",
		OUTSIDE,
	),
	(
		"a sibling whose name starts with the project's",
		"services:\n  web:\n    image: nginx\n    volumes: [\"/var/lib/glyndor/helmly/projects/t1/p10:/x\"]\n",
		OUTSIDE,
	),
	(
		"dot-dot under the project",
		"services:\n  web:\n    image: nginx\n    volumes: [\"/var/lib/glyndor/helmly/projects/t1/p1/../../../../../etc:/x\"]\n",
		DOTDOT,
	),
	("relative dot-dot", "services:\n  web:\n    image: nginx\n    volumes: [\"../../../../../etc:/x\"]\n", DOTDOT),
	("dot-dot under /tmp", "services:\n  web:\n    image: nginx\n    volumes: [\"/tmp/../etc:/x\"]\n", DOTDOT),
	(
		"dot-dot under the webroot",
		"services:\n  web:\n    image: nginx\n    volumes: [\"/var/lib/glyndor/helmly/nginx/webroot/../../../../etc:/x\"]\n",
		DOTDOT,
	),
	(
		"relative dot-dot, long form",
		"services:\n  web:\n    image: nginx\n    volumes:\n      - type: bind\n        source: ../../../../etc\n        target: /x\n",
		DOTDOT,
	),
	(
		"bare relative bind, long form, that climbs",
		"services:\n  web:\n    image: nginx\n    volumes:\n      - type: bind\n        source: data/../../../..\n        target: /x\n",
		DOTDOT,
	),
	(
		"volume-type mount written as a path",
		"services:\n  web:\n    image: nginx\n    volumes:\n      - type: volume\n        source: /etc\n        target: /x\n",
		OUTSIDE,
	),
	("home directory", "services:\n  web:\n    image: nginx\n    volumes: [\"~/:/x\"]\n", "expands to a home directory"),
	(
		"bind without a source",
		"services:\n  web:\n    image: nginx\n    volumes:\n      - type: bind\n        target: /x\n",
		"bind mount with no source",
	),
	(
		"tmpfs mount",
		"services:\n  web:\n    image: nginx\n    volumes:\n      - type: tmpfs\n        target: /x\n",
		"mount type \"tmpfs\"",
	),
	(
		"image mount",
		"services:\n  web:\n    image: nginx\n    volumes:\n      - type: image\n        source: alpine\n        target: /x\n",
		"mount type \"image\"",
	),
	(
		"volume name with a slash",
		"services:\n  web:\n    image: nginx\n    volumes: [\"etc/x:/x\"]\n",
		"neither a host path nor a volume name",
	),
	(
		"named volume that binds the host root",
		r#"
services:
  web:
    image: nginx
    volumes: ["root:/host"]
volumes:
  root:
    driver_opts:
      type: none
      o: bind
      device: /
"#,
		"mounts a host path",
	),
	(
		"named volume with a device path only",
		r#"
services:
  web:
    image: nginx
    volumes: ["root:/host"]
volumes:
  root:
    driver_opts:
      device: /etc
"#,
		"mounts a host path",
	),
	(
		"named volume with rbind among its options",
		r#"
volumes:
  root:
    driver_opts:
      o: "ro,rbind"
services:
  web:
    image: nginx
"#,
		"mounts a host path",
	),
	(
		"volume mounted from an extension block",
		r#"
x-mounts:
  volumes: ["/:/host"]
services:
  web:
    image: nginx
"#,
		OUTSIDE,
	),
];

#[test]
fn bind_sources_outside_the_project_are_refused() {
	assert_refused(CASES);
}
