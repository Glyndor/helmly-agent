//! Rules about the top level of the document: which top-level keys are refused
//! and the shape of the sections the key rules descend into.

use anyhow::{anyhow, Result};
use serde_yaml_ng::{Mapping, Value};

use super::child_path;

/// Check the top-level keys of the document and the shape of its sections.
pub(super) fn check(top: &Mapping) -> Result<()> {
	for (k, v) in top {
		let key = k.as_str().unwrap_or_default();
		if key == "name" {
			return Err(anyhow!(
				"compose_yaml sets the top-level \"name\"; helmly-agent chooses the \
				 project name and does not permit a tenant to set it"
			));
		}
		if key.starts_with("x-podman") {
			return Err(anyhow!(
				"compose_yaml contains the extension {key:?}; helmly-agent does not \
				 permit runner extensions in tenant compose files"
			));
		}
		match key {
			"services" => check_services(v)?,
			"volumes" => check_named_volumes(v)?,
			"networks" => check_networks(v)?,
			"secrets" | "configs" => check_definitions(key, v)?,
			_ => {}
		}
	}
	Ok(())
}

/// `services` is a map of service name to a map of service keys.
fn check_services(value: &Value) -> Result<()> {
	let Value::Mapping(services) = value else {
		return Err(anyhow!(
			"compose_yaml \"services\" must be a mapping of service names"
		));
	};
	for (name, svc) in services {
		if !svc.is_mapping() {
			let path = child_path("services", name.as_str().unwrap_or_default());
			return Err(anyhow!(
				"compose_yaml {path:?} must be a mapping of service keys"
			));
		}
	}
	Ok(())
}

/// Each named volume is empty or a map. A local volume whose options turn it
/// into a bind mount of a host path is refused: that is a bind source the
/// volume rules never see, because the service only names the volume.
fn check_named_volumes(value: &Value) -> Result<()> {
	for (name, def) in definitions("volumes", value)? {
		let path = child_path("volumes", name);
		let Some(opts) = def.and_then(|d| d.get("driver_opts")) else {
			continue;
		};
		let Value::Mapping(opts) = opts else {
			return Err(anyhow!(
				"compose_yaml \"{path}.driver_opts\" must be a mapping"
			));
		};
		for (k, v) in opts {
			let opt = k.as_str().unwrap_or_default();
			let text = match v {
				Value::String(s) => s.as_str(),
				Value::Number(_) | Value::Bool(_) => continue,
				_ => {
					return Err(anyhow!(
						"compose_yaml \"{path}.driver_opts.{opt}\" must be a scalar"
					));
				}
			};
			let binds = opt == "o"
				&& text
					.split(',')
					.any(|o| matches!(o.trim(), "bind" | "rbind"));
			let device_path = opt == "device" && text != "tmpfs";
			if binds || device_path {
				return Err(anyhow!(
					"compose_yaml \"{path}.driver_opts.{opt}\" = {text:?} mounts a host \
					 path; helmly-agent does not permit volume driver options that bind \
					 host paths"
				));
			}
		}
	}
	Ok(())
}

/// Each network is empty or a map. A network that names the host network, or
/// asks for the host driver, would put the service on the host's stack.
fn check_networks(value: &Value) -> Result<()> {
	for (name, def) in definitions("networks", value)? {
		let Some(def) = def else { continue };
		for field in ["name", "driver"] {
			if let Some(v) = def.get(field) {
				let path = format!("networks.{name}.{field}");
				let text = super::expect_str(v, &path)?;
				if text.trim().eq_ignore_ascii_case("host") {
					return Err(anyhow!(
						"compose_yaml {path:?} = {text:?}; helmly-agent does not permit \
						 the host network on tenant containers"
					));
				}
			}
		}
	}
	Ok(())
}

/// `secrets` and `configs` are maps of name to definition map. Their sources
/// (`file`, `environment`) are refused by the key rules wherever they appear.
fn check_definitions(section: &str, value: &Value) -> Result<()> {
	for (name, def) in definitions(section, value)? {
		if def.is_none() {
			let path = child_path(section, name);
			return Err(anyhow!("compose_yaml {path:?} must be a mapping"));
		}
	}
	Ok(())
}

/// The entries of a top-level section: each name with its body, `None` for an
/// empty body. A section that is not a map, or a body that is neither empty nor
/// a map, is refused.
fn definitions<'v>(section: &str, value: &'v Value) -> Result<Vec<(&'v str, Option<&'v Value>)>> {
	let map = match value {
		Value::Mapping(map) => map,
		Value::Null => return Ok(Vec::new()),
		_ => return Err(anyhow!("compose_yaml {section:?} must be a mapping")),
	};
	let mut out = Vec::with_capacity(map.len());
	for (k, v) in map {
		let name = k.as_str().unwrap_or_default();
		match v {
			Value::Null => out.push((name, None)),
			Value::Mapping(_) => out.push((name, Some(v))),
			_ => {
				let path = child_path(section, name);
				return Err(anyhow!("compose_yaml {path:?} must be empty or a mapping"));
			}
		}
	}
	Ok(out)
}
