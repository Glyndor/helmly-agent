//! Privilege and confinement keys: the original deny-list, `init`, `cap_drop`,
//! and every `security_opt` that loosens the default confinement, in both of
//! the separators runners accept.

use super::*;

const OPT: &str = "forbidden security_opt";

const CASES: &[Hostile] = &[
	(
		"privileged",
		r#"
services:
  web:
    image: nginx
    privileged: true
"#,
		"forbidden key \"services.web.privileged\"",
	),
	(
		"cap_add",
		r#"
services:
  web:
    image: nginx
    cap_add: ["SYS_ADMIN"]
"#,
		"forbidden key \"services.web.cap_add\"",
	),
	(
		"devices",
		r#"
services:
  web:
    image: nginx
    devices: ["/dev/fuse"]
"#,
		"forbidden key \"services.web.devices\"",
	),
	(
		"device_cgroup_rules",
		r#"
services:
  web:
    image: nginx
    device_cgroup_rules: ["a *:* rwm"]
"#,
		"forbidden key \"services.web.device_cgroup_rules\"",
	),
	(
		"sysctls",
		r#"
services:
  web:
    image: nginx
    sysctls: {net.ipv4.ip_forward: 1}
"#,
		"forbidden key \"services.web.sysctls\"",
	),
	(
		"cgroup_parent",
		r#"
services:
  web:
    image: nginx
    cgroup_parent: /
"#,
		"forbidden key",
	),
	(
		"tmpfs",
		r#"
services:
  web:
    image: nginx
    tmpfs: /run
"#,
		"forbidden key \"services.web.tmpfs\"",
	),
	(
		"init false",
		r#"
services:
  web:
    image: nginx
    init: false
"#,
		"must be `true` when present",
	),
	(
		"cap_drop ALL",
		r#"
services:
  web:
    image: nginx
    cap_drop: ["ALL"]
"#,
		"dropping all caps",
	),
	(
		"cap_drop all in lower case",
		r#"
services:
  web:
    image: nginx
    cap_drop: [all]
"#,
		"dropping all caps",
	),
	(
		"cap_drop CAP_ALL",
		r#"
services:
  web:
    image: nginx
    cap_drop: [CAP_ALL]
"#,
		"dropping all caps",
	),
	("seccomp unconfined", SECCOMP_UNCONFINED, OPT),
	("seccomp unconfined with a colon", SECCOMP_COLON, OPT),
	("seccomp profile path", SECCOMP_PATH, OPT),
	("apparmor unconfined with a colon", APPARMOR_COLON, OPT),
	("label disable", LABEL_DISABLE, OPT),
	("label disable with a colon", LABEL_DISABLE_COLON, OPT),
	("label type", LABEL_TYPE, OPT),
	("unmask", UNMASK, OPT),
	("systempaths unconfined", SYSTEMPATHS, OPT),
];

const SECCOMP_UNCONFINED: &str =
	"services:\n  web:\n    image: nginx\n    security_opt: [\"seccomp=unconfined\"]\n";
const SECCOMP_COLON: &str =
	"services:\n  web:\n    image: nginx\n    security_opt: [\"seccomp:unconfined\"]\n";
const SECCOMP_PATH: &str =
	"services:\n  web:\n    image: nginx\n    security_opt: [\"seccomp=/tmp/profile.json\"]\n";
const APPARMOR_COLON: &str =
	"services:\n  web:\n    image: nginx\n    security_opt: [\"apparmor:unconfined\"]\n";
const LABEL_DISABLE: &str =
	"services:\n  web:\n    image: nginx\n    security_opt: [\"label=disable\"]\n";
const LABEL_DISABLE_COLON: &str =
	"services:\n  web:\n    image: nginx\n    security_opt: [\"label:disable\"]\n";
const LABEL_TYPE: &str =
	"services:\n  web:\n    image: nginx\n    security_opt: [\"label=type:spc_t\"]\n";
const UNMASK: &str = "services:\n  web:\n    image: nginx\n    security_opt: [\"unmask=ALL\"]\n";
const SYSTEMPATHS: &str =
	"services:\n  web:\n    image: nginx\n    security_opt: [\"systempaths=unconfined\"]\n";

#[test]
fn privilege_and_confinement_loosening_is_refused() {
	assert_refused(CASES);
}
