//! Compose validation tests.
//!
//! Each `hostile_*` file is one family of composes that must be refused, each
//! case with a fragment of the refusal it must get, so a case refused by the
//! wrong rule fails. `legitimate` is the corpus that must keep passing, and it
//! holds the neighbour just inside every refusal.

use super::*;

mod canonical;
mod hostile_extensions;
mod hostile_files;
mod hostile_hosts;
mod hostile_interpolation;
mod hostile_namespaces;
mod hostile_ports;
mod hostile_security;
mod hostile_shapes;
mod hostile_tags;
mod hostile_volumes;
mod legitimate;

/// The project directory the hostile and legitimate corpora are checked
/// against. It does not exist on a test machine, so nothing resolves through a
/// link and the checks are about the text of each path.
pub(super) const PROJECT: &str = "/var/lib/glyndor/helmly/projects/t1/p1";

/// helmly-agent's own ports in the corpora: listener, WireGuard, setup port.
pub(super) const RESERVED: &[u16] = &[9090, 51820, 19443];

/// A compose that must be refused: name, document, fragment of the refusal.
pub(super) type Hostile = (&'static str, &'static str, &'static str);

pub(super) fn policy() -> ComposePolicy<'static> {
	ComposePolicy {
		project_dir: std::path::Path::new(PROJECT),
		reserved_ports: RESERVED,
	}
}

/// Every case must be refused, and by the rule its fragment names. All the
/// cases run before the assertion so a failure lists every case that broke.
pub(super) fn assert_refused(cases: &[Hostile]) {
	let mut wrong = Vec::new();
	for (name, yaml, fragment) in cases {
		match validate_compose(yaml, &policy()) {
			Ok(()) => wrong.push(format!("{name}: accepted")),
			Err(e) => {
				let msg = format!("{e:#}");
				if !msg.contains(fragment) {
					wrong.push(format!("{name}: refused for another reason: {msg}"));
				}
			}
		}
	}
	assert!(
		wrong.is_empty(),
		"hostile cases not refused as expected:\n{}",
		wrong.join("\n")
	);
}

/// Every case must pass.
pub(super) fn assert_accepted(cases: &[(&str, &str)]) {
	let wrong: Vec<String> = cases
		.iter()
		.filter_map(|(name, yaml)| {
			validate_compose(yaml, &policy())
				.err()
				.map(|e| format!("{name}: {e:#}"))
		})
		.collect();
	assert!(
		wrong.is_empty(),
		"legitimate cases refused:\n{}",
		wrong.join("\n")
	);
}
