//! Validation of a tenant compose file before helmly-agent writes it to disk and
//! hands it to the compose runner.
//!
//! The check is a deny-list over the parsed document. A deny-list only holds
//! while the validator reads exactly what the runner applies, so anything that
//! lets the two read different things is refused outright: YAML tags, merge
//! keys, interpolation, references to a second file, and values whose YAML shape
//! a rule does not expect. Every refusal names the key and the reason, and every
//! doubt about shape is a refusal.

mod document;
mod hosts;
mod keys;
mod paths;
mod ports;
mod structure;
mod values;
mod volumes;

use std::path::Path;

use anyhow::{anyhow, Result};
use serde_yaml_ng::Value;

/// What the validator needs to know about the host the compose file runs on.
pub(crate) struct ComposePolicy<'a> {
	/// The directory the runner uses as the compose project directory. Relative
	/// bind sources resolve against it, and absolute ones must resolve under it,
	/// under the nginx webroot, or under `/tmp`.
	pub project_dir: &'a Path,
	/// Host ports helmly-agent itself listens on. A tenant service may not publish
	/// on any of them, whatever the protocol or host address.
	pub reserved_ports: &'a [u16],
}

/// Validate a tenant `compose_yaml` payload.
///
/// Returns `Err` with a message naming the offending key and the reason when
/// the document uses a construct helmly-agent does not permit on tenant
/// containers, or uses a permitted key in a shape the rules cannot read.
pub(crate) fn validate_compose(yaml: &str, policy: &ComposePolicy<'_>) -> Result<()> {
	let root: Value = serde_yaml_ng::from_str(yaml)
		.map_err(|e| anyhow!("compose_yaml is not valid YAML: {e}"))?;
	let Value::Mapping(top) = &root else {
		return Err(anyhow!("compose_yaml must be a mapping at the top level"));
	};
	structure::check(&root, "")?;
	document::check(top)?;
	keys::walk(&root, &keys::Place::root(), policy)?;
	Ok(())
}

/// The dotted path of `key` under `parent`, as printed in refusals.
fn child_path(parent: &str, key: &str) -> String {
	if parent.is_empty() {
		key.to_string()
	} else {
		format!("{parent}.{key}")
	}
}

/// The string inside `value`, or a refusal that names `path` and the shape.
fn expect_str<'v>(value: &'v Value, path: &str) -> Result<&'v str> {
	match value {
		Value::String(s) => Ok(s),
		_ => Err(anyhow!(
			"compose_yaml {path:?} must be a string; helmly-agent refuses any other shape here"
		)),
	}
}

/// The sequence inside `value`, or a refusal that names `path` and the shape.
fn expect_seq<'v>(value: &'v Value, path: &str) -> Result<&'v [Value]> {
	match value {
		Value::Sequence(seq) => Ok(seq),
		_ => Err(anyhow!(
			"compose_yaml {path:?} must be a list; helmly-agent refuses any other shape here"
		)),
	}
}

#[cfg(test)]
mod tests;
