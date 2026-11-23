use super::*;

#[test]
fn a_configured_url_is_used_in_ci_and_outside_it() {
	let url = "postgres://u:p@localhost/db";
	assert_eq!(access(Some("true"), Some(url)), Ok(Access::Use(url.into())));
	assert_eq!(access(None, Some(url)), Ok(Access::Use(url.into())));
}

#[test]
fn no_url_skips_on_a_workstation() {
	assert_eq!(access(None, None), Ok(Access::Skip));
	assert_eq!(access(Some("false"), None), Ok(Access::Skip));
	assert_eq!(access(Some(""), None), Ok(Access::Skip));
}

#[test]
fn no_url_fails_in_ci() {
	assert!(access(Some("true"), None).is_err());
	assert!(access(Some("1"), None).is_err());
}

#[test]
fn an_empty_url_is_no_url() {
	// A CI variable filled from a secret that does not exist arrives empty.
	assert!(access(Some("true"), Some("")).is_err());
	assert_eq!(access(None, Some("")), Ok(Access::Skip));
}

#[test]
fn the_failure_names_both_variables() {
	let reason = access(Some("true"), None).unwrap_err();
	assert!(reason.contains("CI") && reason.contains("DATABASE_URL"));
}
