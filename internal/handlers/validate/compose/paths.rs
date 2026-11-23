//! Confinement of host paths named by bind mounts.
//!
//! A source is resolved the way the runtime will resolve it: relative to the
//! project directory, through every symbolic link that exists on disk today.
//! Only then is it compared, component by component, with the permitted roots,
//! which are resolved the same way. `..` is refused before any of that, and a
//! `~` path is refused because it expands to a home directory outside the
//! project.

use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, Result};

/// The org nginx webroot, which tenant services may mount.
const WEBROOT: &str = "/var/lib/glyndor/helmly/nginx/webroot";

/// Scratch space a tenant service may mount.
const SCRATCH: &str = "/tmp";

/// Accept `src` when it resolves under `project_dir`, the webroot or `/tmp`.
pub(super) fn check_bind_source(src: &str, project_dir: &Path, path: &str) -> Result<()> {
	let refuse = |why: &str| {
		anyhow!(
			"compose_yaml {path:?} source {src:?} {why}; helmly-agent rejects host-path \
			 volumes outside the project dir, {WEBROOT}, or {SCRATCH}"
		)
	};
	if src.is_empty() {
		return Err(refuse("is empty"));
	}
	if src.starts_with('~') {
		return Err(refuse("expands to a home directory"));
	}
	// Collecting the components drops `.` so that it never reaches `resolve`.
	let joined: PathBuf = project_dir.join(src).components().collect();
	if joined.components().any(|c| c == Component::ParentDir) {
		return Err(refuse("contains `..`"));
	}
	let resolved = resolve(&joined).map_err(|e| refuse(&e))?;
	for root in [project_dir, Path::new(WEBROOT), Path::new(SCRATCH)] {
		let root = resolve(root).map_err(|e| refuse(&e))?;
		if resolved.starts_with(&root) {
			return Ok(());
		}
	}
	Err(refuse(&format!(
		"resolves to {} and is outside the tenant root",
		resolved.display()
	)))
}

/// `path` with every symbolic link that exists on disk resolved.
///
/// The longest prefix that exists is canonicalised, and the components after it,
/// which do not exist yet, are appended as written: the runtime creates them
/// there. A prefix that exists as a dangling link fails to canonicalise and is
/// refused, because the runtime would create the link's target instead.
fn resolve(path: &Path) -> std::result::Result<PathBuf, String> {
	let mut existing = path.to_path_buf();
	let mut missing: Vec<std::ffi::OsString> = Vec::new();
	loop {
		match std::fs::symlink_metadata(&existing) {
			Ok(_) => break,
			Err(e) if e.kind() == ErrorKind::NotFound => {
				let Some(name) = existing.file_name() else {
					return Err("has no existing ancestor".to_string());
				};
				missing.push(name.to_os_string());
				if !existing.pop() {
					return Err("has no existing ancestor".to_string());
				}
			}
			Err(e) => return Err(format!("cannot be inspected ({e})")),
		}
	}
	let mut out = std::fs::canonicalize(&existing)
		.map_err(|e| format!("cannot be resolved at {} ({e})", existing.display()))?;
	for name in missing.iter().rev() {
		out.push(name);
	}
	Ok(out)
}
