//! Key rules, applied at every depth of the document. A key that a runner
//! would honour anywhere is checked everywhere, so a rule cannot be skipped by
//! moving the key into an extension block whose content is later aliased into a
//! service.

use anyhow::{anyhow, Result};
use serde_yaml_ng::Value;

use super::{child_path, hosts, ports, values, volumes, ComposePolicy};

/// Keys whose presence at any depth is refused, whatever their value.
const DENY_KEYS: &[&str] = &[
	"privileged",
	"cap_add",
	"cgroup_parent",
	"devices",
	"device_cgroup_rules",
	"sysctls",
	"tmpfs",
	// A runtime is a program the runner executes on the host as the tenant,
	// outside any container.
	"runtime",
	// The share of another container's volumes, outside the volume rules.
	"volumes_from",
	// A second file the runner reads and this validator never sees.
	"extends",
	"include",
	"env_file",
	"label_file",
	// A build runs on the host, from a context and a Dockerfile the tenant picks.
	"build",
];

/// Where the walker stands: the dotted path, the depth (0 for the top level)
/// and whether it is inside a `secrets` or `configs` section.
pub(super) struct Place {
	path: String,
	depth: usize,
	in_secrets: bool,
}

impl Place {
	/// The top of the document.
	pub(super) fn root() -> Self {
		Self {
			path: String::new(),
			depth: 0,
			in_secrets: false,
		}
	}

	fn child(&self, key: &str) -> Self {
		Self {
			path: child_path(&self.path, key),
			depth: self.depth + 1,
			// A service may be called `secrets`; that name opens no section.
			in_secrets: self.in_secrets
				|| ((key == "secrets" || key == "configs") && self.path != "services"),
		}
	}
}

/// Apply the key rules to every key under `node`. The structural pass has
/// already guaranteed that every key is a plain string.
pub(super) fn walk(node: &Value, at: &Place, policy: &ComposePolicy<'_>) -> Result<()> {
	match node {
		Value::Mapping(map) => {
			for (k, v) in map {
				let key = k.as_str().unwrap_or_default();
				let here = at.child(key);
				check_key(key, v, at, &here, policy)?;
				walk(v, &here, policy)?;
			}
		}
		Value::Sequence(seq) => {
			for (i, v) in seq.iter().enumerate() {
				let here = Place {
					path: format!("{}[{i}]", at.path),
					depth: at.depth,
					in_secrets: at.in_secrets,
				};
				walk(v, &here, policy)?;
			}
		}
		_ => {}
	}
	Ok(())
}

/// The rule for one key. `parent` is where the key sits, `here` is the key.
fn check_key(
	key: &str,
	value: &Value,
	parent: &Place,
	here: &Place,
	policy: &ComposePolicy<'_>,
) -> Result<()> {
	let path = here.path.as_str();
	if DENY_KEYS.contains(&key) {
		return Err(anyhow!(
			"compose_yaml contains forbidden key {path:?} ({key:?}); \
			 helmly-agent does not permit this key on tenant containers"
		));
	}
	if key.starts_with("x-") && parent.depth > 0 {
		return Err(anyhow!(
			"compose_yaml contains the extension {path:?}; helmly-agent permits \
			 `x-` keys only at the top level"
		));
	}
	if parent.in_secrets && (key == "file" || key == "environment") {
		return Err(anyhow!(
			"compose_yaml {path:?} reads a secret or config from the host; \
			 helmly-agent does not permit `file` or `environment` sources"
		));
	}
	match key {
		"init" => values::init(value, path),
		"network_mode" | "pid" | "ipc" | "uts" | "cgroup" => values::namespace(key, value, path),
		"userns_mode" => values::userns(value, path),
		"cap_drop" => values::cap_drop(value, path),
		"security_opt" => values::security_opt(value, path),
		"labels" => values::labels(value, path),
		"extra_hosts" => hosts::check(value, path),
		"ports" => ports::check(value, path, policy.reserved_ports),
		// The top-level `volumes` is the map of named volumes, checked with the
		// rest of the top level; everywhere else it is a service's mount list.
		"volumes" if parent.depth > 0 => volumes::check(value, path, policy),
		_ => Ok(()),
	}
}
