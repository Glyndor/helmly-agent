//! Rules on the value of a key. Each rule accepts only the YAML shape it can
//! read and refuses any other, so a value cannot pass by being written as a
//! list where a string is expected, or the reverse.

use anyhow::{anyhow, Result};
use serde_yaml_ng::Value;

use super::{expect_seq, expect_str};

/// Namespace modes that join the host's namespace or another container's.
/// `ns:` names a namespace by path, which includes the host's.
const SHARED_NAMESPACE_PREFIXES: &[&str] = &["container:", "service:", "ns:"];

/// Network modes that take options after a colon. The options can open a
/// route from the container to the host's loopback.
const NETWORK_MODES_WITH_OPTIONS: &[&str] = &["slirp4netns:", "pasta:"];

/// Label keys that hand a container to a host-side service.
const DENY_LABELS: &[&str] = &["io.containers.autoupdate"];

/// `init` may be absent or `true`. `false`, and anything that is not a YAML
/// boolean (`"no"`, `0`), is refused: runners disagree on how to read those.
pub(super) fn init(value: &Value, path: &str) -> Result<()> {
	match value {
		Value::Bool(true) => Ok(()),
		_ => Err(anyhow!(
			"compose_yaml {path:?} must be `true` when present; helmly-agent requires \
			 an init process on tenant containers"
		)),
	}
}

/// `network_mode`, `pid`, `ipc`, `uts` and `cgroup` may not share a namespace
/// with the host or with another container, and `network_mode` may not carry
/// options.
pub(super) fn namespace(key: &str, value: &Value, path: &str) -> Result<()> {
	let raw = expect_str(value, path)?;
	let mode = raw.trim().to_ascii_lowercase();
	let shared = mode == "host"
		|| mode == "container"
		|| mode == "service"
		|| SHARED_NAMESPACE_PREFIXES
			.iter()
			.any(|p| mode.starts_with(p));
	if shared {
		return Err(anyhow!(
			"compose_yaml contains forbidden value {path:?} = {raw:?}; helmly-agent \
			 does not permit sharing a namespace with the host or another container"
		));
	}
	if key == "network_mode"
		&& NETWORK_MODES_WITH_OPTIONS
			.iter()
			.any(|p| mode.starts_with(p))
	{
		return Err(anyhow!(
			"compose_yaml contains forbidden value {path:?} = {raw:?}; helmly-agent \
			 does not permit network mode options on tenant containers"
		));
	}
	Ok(())
}

/// `userns_mode` may only be `auto`.
pub(super) fn userns(value: &Value, path: &str) -> Result<()> {
	let raw = expect_str(value, path)?;
	if raw != "auto" {
		return Err(anyhow!(
			"compose_yaml contains forbidden value {path:?} = {raw:?}; \
			 only userns_mode: auto is permitted"
		));
	}
	Ok(())
}

/// `cap_drop` is a list of capability names, and `ALL` is refused in any case
/// and with or without the `CAP_` prefix.
pub(super) fn cap_drop(value: &Value, path: &str) -> Result<()> {
	for (i, item) in expect_seq(value, path)?.iter().enumerate() {
		let cap = expect_str(item, &format!("{path}[{i}]"))?;
		let cap = cap.trim().to_ascii_uppercase();
		if cap.strip_prefix("CAP_").unwrap_or(&cap) == "ALL" {
			return Err(anyhow!(
				"compose_yaml contains cap_drop: [ALL] at {path:?}; \
				 helmly-agent does not permit dropping all caps"
			));
		}
	}
	Ok(())
}

/// `security_opt` is a list of `key=value` or `key:value` options (runners
/// accept both separators). Refused: any `seccomp` profile (the default one is
/// what applies when the option is absent), `apparmor` and `systempaths`
/// set to `unconfined`, `label` set to `disable` or to a type, and any
/// `unmask`.
pub(super) fn security_opt(value: &Value, path: &str) -> Result<()> {
	for (i, item) in expect_seq(value, path)?.iter().enumerate() {
		let raw = expect_str(item, &format!("{path}[{i}]"))?;
		let opt = raw.trim().to_ascii_lowercase();
		let (name, val) = match opt.find([':', '=']) {
			Some(at) => (&opt[..at], opt[at + 1..].trim()),
			None => (opt.as_str(), ""),
		};
		let forbidden = match name.trim() {
			"seccomp" | "unmask" => true,
			"apparmor" | "systempaths" => val == "unconfined",
			"label" => val == "disable" || val.starts_with("type:"),
			_ => false,
		};
		if forbidden {
			return Err(anyhow!(
				"compose_yaml contains forbidden security_opt {raw:?} at {path:?}"
			));
		}
	}
	Ok(())
}

/// `labels` is a map or a list of `key=value`. Labels that enrol the container
/// in a host-side service are refused.
pub(super) fn labels(value: &Value, path: &str) -> Result<()> {
	let names: Vec<&str> = match value {
		Value::Mapping(map) => map.keys().map(|k| k.as_str().unwrap_or_default()).collect(),
		Value::Sequence(seq) => {
			let mut out = Vec::with_capacity(seq.len());
			for (i, item) in seq.iter().enumerate() {
				let entry = expect_str(item, &format!("{path}[{i}]"))?;
				out.push(entry.split_once('=').map_or(entry, |(k, _)| k));
			}
			out
		}
		_ => {
			return Err(anyhow!(
				"compose_yaml {path:?} must be a mapping or a list; helmly-agent refuses \
				 any other shape here"
			));
		}
	};
	for name in names {
		if DENY_LABELS.contains(&name.trim()) {
			return Err(anyhow!(
				"compose_yaml {path:?} sets the label {name:?}; helmly-agent does not \
				 permit it on tenant containers"
			));
		}
	}
	Ok(())
}
