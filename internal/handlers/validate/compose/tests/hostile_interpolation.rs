//! Interpolation: the runner substitutes `$VAR` and `${VAR}` from its own
//! environment after validation, so no rule can know the value it judges.

use super::*;

const CASES: &[Hostile] = &[
	(
		"braced variable in network_mode",
		r#"
services:
  web:
    image: nginx
    network_mode: ${NM}
"#,
		"unescaped `$` at \"services.web.network_mode\"",
	),
	(
		"bare variable in network_mode",
		r#"
services:
  web:
    image: nginx
    network_mode: $NM
"#,
		"unescaped `$`",
	),
	(
		"variable as a volume source",
		r#"
services:
  web:
    image: nginx
    volumes:
      - "${SRC}:/host"
"#,
		"unescaped `$` at \"services.web.volumes[0]\"",
	),
	(
		"variable with a default",
		r#"
services:
  web:
    image: nginx
    pid: ${P:-host}
"#,
		"unescaped `$`",
	),
	(
		"variable that reads the daemon's environment",
		r#"
services:
  web:
    image: nginx
    environment:
      T: ${INTERNAL_TOKEN}
"#,
		"unescaped `$` at \"services.web.environment.T\"",
	),
	(
		"variable in a key",
		r#"
services:
  web:
    image: nginx
    labels:
      ${K}: v
"#,
		"unescaped `$`",
	),
	(
		"escaped dollar followed by a variable",
		r#"
services:
  web:
    image: nginx
    command: echo $$HOME ${X}
"#,
		"unescaped `$`",
	),
	(
		"lone dollar",
		r#"
services:
  web:
    image: nginx
    command: echo $1
"#,
		"unescaped `$`",
	),
];

#[test]
fn interpolation_is_refused() {
	assert_refused(CASES);
}
