//! YAML constructs a runner reads differently from the validator: tags at any
//! level, merge keys, keys that are not strings, and documents that are not a
//! mapping.

use super::*;

const CASES: &[Hostile] = &[
	(
		"tag on a namespace value",
		r#"
services:
  web:
    image: nginx
    network_mode: !override host
"#,
		"YAML tag !override",
	),
	(
		"tag on pid",
		r#"
services:
  web:
    image: nginx
    pid: !override host
"#,
		"YAML tag !override",
	),
	(
		"reset tag on ipc",
		r#"
services:
  web:
    image: nginx
    ipc: !reset host
"#,
		"YAML tag !reset",
	),
	(
		"tag on userns_mode",
		r#"
services:
  web:
    image: nginx
    userns_mode: !override host
"#,
		"YAML tag",
	),
	(
		"tag on security_opt",
		r#"
services:
  web:
    image: nginx
    security_opt: !override ["seccomp=unconfined"]
"#,
		"YAML tag",
	),
	(
		"tag on cap_drop",
		r#"
services:
  web:
    image: nginx
    cap_drop: !override ["ALL"]
"#,
		"YAML tag",
	),
	(
		"tag on the volume list",
		r#"
services:
  web:
    image: nginx
    volumes: !override ["/:/host"]
"#,
		"YAML tag",
	),
	(
		"tag on one volume entry",
		r#"
services:
  web:
    image: nginx
    volumes:
      - !reset "/:/host"
"#,
		"YAML tag",
	),
	(
		"tag on a whole service",
		r#"
services:
  web: !override
    image: nginx
    privileged: true
"#,
		"YAML tag",
	),
	(
		"tag on the services section",
		r#"
services: !override
  web:
    image: nginx
    privileged: true
"#,
		"YAML tag",
	),
	(
		"tag on a key",
		r#"
services:
  web:
    image: nginx
    !x privileged: true
"#,
		"YAML tag !x",
	),
	(
		"any custom tag",
		r#"
services:
  web:
    image: nginx
    environment: !anything {A: b}
"#,
		"YAML tag !anything",
	),
	(
		"merge key that brings in a volume",
		r#"
services:
  web:
    image: nginx
    <<: {volumes: ["/:/host"]}
"#,
		"merge key",
	),
	(
		"merge key from an anchor",
		r#"
x-base: &base
  network_mode: bridge
services:
  web:
    image: nginx
    <<: *base
"#,
		"merge key",
	),
	(
		"number as a key",
		r#"
services:
  web:
    image: nginx
    1: host
"#,
		"not a string",
	),
	(
		"null as a key",
		r#"
services:
  web:
    image: nginx
    ~: host
"#,
		"not a string",
	),
	(
		"document that is a list",
		"- services: {}\n",
		"mapping at the top level",
	),
	("empty document", "", "mapping at the top level"),
];

#[test]
fn hostile_yaml_constructs_are_refused() {
	assert_refused(CASES);
}

/// An alias is expanded by the parser, so the value it copies is checked where
/// it lands, and anchors need no rule of their own.
#[test]
fn alias_of_a_forbidden_value_is_refused_where_it_lands() {
	assert_refused(&[(
		"alias of host",
		r#"
x-mode: &mode host
services:
  web:
    image: nginx
    network_mode: *mode
"#,
		"services.web.network_mode",
	)]);
}

/// Duplicate keys need no rule: the parser refuses them at any depth.
#[test]
fn duplicate_keys_are_refused_by_the_parser() {
	assert_refused(&[(
		"duplicate key in a service",
		r#"
services:
  web:
    image: nginx
    network_mode: bridge
    network_mode: host
"#,
		"duplicate entry",
	)]);
}
