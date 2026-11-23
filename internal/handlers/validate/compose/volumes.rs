//! A service's `volumes` list, in its short and long forms. Every entry that
//! names a host path has that path confined by `paths`.

use anyhow::{anyhow, Result};
use serde_yaml_ng::{Mapping, Value};

use super::{expect_seq, expect_str, paths, ComposePolicy};

/// Long-form mount types helmly-agent permits. A `tmpfs` mount is refused like the
/// `tmpfs` key; any other type is refused because no rule here reads it.
const MOUNT_TYPES: &[&str] = &["bind", "volume"];

/// Check every entry of a service's `volumes` list.
pub(super) fn check(value: &Value, path: &str, policy: &ComposePolicy<'_>) -> Result<()> {
	for (i, entry) in expect_seq(value, path)?.iter().enumerate() {
		let here = format!("{path}[{i}]");
		match entry {
			Value::String(s) => short_form(s, &here, policy)?,
			Value::Mapping(m) => long_form(m, &here, policy)?,
			_ => {
				return Err(anyhow!(
					"compose_yaml {here:?} must be a string or a mapping; helmly-agent \
					 refuses any other shape here"
				));
			}
		}
	}
	Ok(())
}

/// `source:target[:options]`. A source that starts with `/`, `.` or `~` is a
/// host path; anything else is a named volume. An entry without a colon is an
/// anonymous volume and names no host path.
fn short_form(entry: &str, path: &str, policy: &ComposePolicy<'_>) -> Result<()> {
	let Some((src, _)) = entry.split_once(':') else {
		return Ok(());
	};
	if is_host_path(src) {
		return paths::check_bind_source(src, policy.project_dir, path);
	}
	if src.is_empty() || src.contains('/') {
		return Err(anyhow!(
			"compose_yaml {path:?} source {src:?} is neither a host path nor a \
			 volume name"
		));
	}
	Ok(())
}

/// `{type, source, target, ...}`. A `bind` source is always a host path,
/// relative ones against the project directory; a `volume` source is a name
/// unless it is written as a path.
fn long_form(entry: &Mapping, path: &str, policy: &ComposePolicy<'_>) -> Result<()> {
	let Some(kind) = entry.get("type") else {
		return Err(anyhow!("compose_yaml {path:?} has no mount type"));
	};
	let kind = expect_str(kind, &format!("{path}.type"))?;
	if !MOUNT_TYPES.contains(&kind) {
		return Err(anyhow!(
			"compose_yaml {path:?} has mount type {kind:?}; helmly-agent permits only \
			 bind and volume mounts"
		));
	}
	let src = match entry.get("source") {
		None | Some(Value::Null) => None,
		Some(v) => Some(expect_str(v, &format!("{path}.source"))?),
	};
	match (kind, src) {
		("bind", None) => Err(anyhow!(
			"compose_yaml {path:?} is a bind mount with no source"
		)),
		("bind", Some(src)) => paths::check_bind_source(src, policy.project_dir, path),
		(_, Some(src)) if is_host_path(src) || src.contains('/') => {
			paths::check_bind_source(src, policy.project_dir, path)
		}
		_ => Ok(()),
	}
}

fn is_host_path(src: &str) -> bool {
	src.starts_with('/') || src.starts_with('.') || src.starts_with('~')
}
