//! Keys that make the runner read a second file this validator never sees, or
//! run something on the host: `extends`, `include`, `env_file`, `label_file`,
//! `build`, `runtime`, and secret or config sources.

use super::*;

const CASES: &[Hostile] = &[
	(
		"extends from another file",
		r#"
services:
  web:
    extends:
      file: ../../../../etc/glyndor/hostile.yml
      service: base
"#,
		"forbidden key \"services.web.extends\"",
	),
	(
		"extends from the same file",
		r#"
services:
  base:
    image: nginx
  web:
    extends: base
"#,
		"forbidden key \"services.web.extends\"",
	),
	(
		"include",
		r#"
include:
  - /etc/glyndor/hostile.yml
services:
  web:
    image: nginx
"#,
		"forbidden key \"include\"",
	),
	(
		"env_file",
		r#"
services:
  web:
    image: nginx
    env_file: /etc/glyndor/helmly/agent.env
"#,
		"forbidden key \"services.web.env_file\"",
	),
	(
		"label_file",
		r#"
services:
  web:
    image: nginx
    label_file: /etc/shadow
"#,
		"forbidden key \"services.web.label_file\"",
	),
	(
		"build context",
		r#"
services:
  web:
    build:
      context: /
"#,
		"forbidden key \"services.web.build\"",
	),
	(
		"build with an inline Dockerfile",
		r#"
services:
  web:
    build:
      context: .
      dockerfile_inline: "FROM alpine"
"#,
		"forbidden key \"services.web.build\"",
	),
	(
		"build as a string",
		r#"
services:
  web:
    build: .
"#,
		"forbidden key \"services.web.build\"",
	),
	(
		"runtime binary",
		r#"
services:
  web:
    image: nginx
    runtime: /var/lib/glyndor/helmly/projects/t1/p1/data/runtime
"#,
		"forbidden key \"services.web.runtime\"",
	),
	(
		"secret from a host file",
		r#"
secrets:
  s:
    file: /etc/shadow
services:
  web:
    image: nginx
    secrets: [s]
"#,
		"reads a secret or config from the host",
	),
	(
		"config from a host file",
		r#"
configs:
  c:
    file: /etc/glyndor/helmly/dashboard-keyring
services:
  web:
    image: nginx
    configs: [c]
"#,
		"reads a secret or config from the host",
	),
	(
		"secret from the runner's environment",
		r#"
secrets:
  s:
    environment: INTERNAL_TOKEN
services:
  web:
    image: nginx
    secrets: [s]
"#,
		"reads a secret or config from the host",
	),
	(
		"secret that is not a mapping",
		r#"
secrets:
  s: /etc/shadow
services:
  web:
    image: nginx
"#,
		"\"secrets.s\" must be empty or a mapping",
	),
	(
		"secret with an empty body",
		r#"
secrets:
  s:
services:
  web:
    image: nginx
"#,
		"\"secrets.s\" must be a mapping",
	),
];

#[test]
fn second_files_and_host_side_execution_are_refused() {
	assert_refused(CASES);
}
