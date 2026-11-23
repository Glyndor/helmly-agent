//! Watched values written in a YAML shape the rule does not expect. Each one
//! passed before because the rule only matched the expected shape.

use super::*;

const CASES: &[Hostile] = &[
	(
		"init written as a YAML 1.1 boolean",
		r#"
services:
  web:
    image: nginx
    init: no
"#,
		"must be `true` when present",
	),
	(
		"init as a number",
		r#"
services:
  web:
    image: nginx
    init: 0
"#,
		"must be `true` when present",
	),
	(
		"cap_drop as a string",
		r#"
services:
  web:
    image: nginx
    cap_drop: ALL
"#,
		"\"services.web.cap_drop\" must be a list",
	),
	(
		"security_opt as a string",
		r#"
services:
  web:
    image: nginx
    security_opt: seccomp=unconfined
"#,
		"\"services.web.security_opt\" must be a list",
	),
	(
		"security_opt entry as a mapping",
		r#"
services:
  web:
    image: nginx
    security_opt:
      - {seccomp: unconfined}
"#,
		"\"services.web.security_opt[0]\" must be a string",
	),
	(
		"volumes as a string",
		r#"
services:
  web:
    image: nginx
    volumes: "/:/host"
"#,
		"\"services.web.volumes\" must be a list",
	),
	(
		"network_mode as a list",
		r#"
services:
  web:
    image: nginx
    network_mode: [host]
"#,
		"\"services.web.network_mode\" must be a string",
	),
	(
		"userns_mode as a mapping",
		r#"
services:
  web:
    image: nginx
    userns_mode: {mode: host}
"#,
		"\"services.web.userns_mode\" must be a string",
	),
	(
		"long volume source as a list",
		r#"
services:
  web:
    image: nginx
    volumes:
      - type: bind
        source: ["/"]
        target: /h
"#,
		"\"services.web.volumes[0].source\" must be a string",
	),
	(
		"long volume without a type",
		r#"
services:
  web:
    image: nginx
    volumes:
      - source: /etc/passwd
        target: /in/container
"#,
		"has no mount type",
	),
	(
		"volume entry as a number",
		r#"
services:
  web:
    image: nginx
    volumes: [1]
"#,
		"must be a string or a mapping",
	),
	(
		"services as a list",
		r#"
services:
  - image: nginx
    privileged: false
"#,
		"\"services\" must be a mapping of service names",
	),
	(
		"service as a string",
		r#"
services:
  web: nginx
"#,
		"\"services.web\" must be a mapping of service keys",
	),
	(
		"extra_hosts as a string",
		r#"
services:
  web:
    image: nginx
    extra_hosts: "h:127.0.0.1"
"#,
		"must be a list or a mapping",
	),
	(
		"ports entry as a list",
		r#"
services:
  web:
    image: nginx
    ports:
      - ["9090", "80"]
"#,
		"must be a port, a string or a mapping",
	),
	(
		"labels as a string",
		r#"
services:
  web:
    image: nginx
    labels: io.containers.autoupdate=registry
"#,
		"must be a mapping or a list",
	),
];

#[test]
fn unexpected_shapes_are_refused() {
	assert_refused(CASES);
}
