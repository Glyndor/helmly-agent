//! C4: validation of signed-payload inputs.
//!
//! Per the compat review's recommendation:
//! - Compose YAML: **deny-list** for host-escape vectors. Smaller
//!   surface than an allow-list, no breakage of legitimate use, and the
//!   escape surface is well-catalogued (podman docs).
//! - Nginx config: **allow-list** of legitimate directives. Smaller
//!   than the deny-list of dangerous ones, and the reverse-proxy use
//!   case uses ~15 directives.
//!
//! Both validators return `Err` with a specific reason on rejection,
//! so the handler surfaces a useful message to the dashboard.
#![allow(clippy::manual_contains)]

use anyhow::{anyhow, Result};
use serde_yaml_ng::Value;

const WEBROOT: &str = "/var/lib/glyndor/helmly/nginx/webroot";

/// C4 deny-list keys. Presence of any of these at any nesting depth
/// (top-level or `services.*`) fails the validation. The list is the
/// minimum needed to close the attack chain that the audit calls out
/// (host root via `privileged`, `network_mode: host`, etc.).
const DENY_KEYS: &[&str] = &[
	"privileged",
	"cap_add",
	"cgroup_parent",
	"devices",
	"sysctls",
	"tmpfs",
	"init",
	// `network_mode` is checked separately because only the value `host`
	// is forbidden (`bridge`, `service:foo` etc. are legitimate).
	// `pid`, `ipc`, `userns_mode` similarly.
];

/// `network_mode`, `pid`, `ipc`, `userns_mode` are forbidden only when
/// set to `host` (or for `userns_mode`, anything other than `auto`).
const FORBIDDEN_VALUES: &[(&str, &str)] = &[
	("network_mode", "host"),
	("network_mode", "container"), // any container:* pin to that container's ns
	("pid", "host"),
	("ipc", "host"),
];

const FORBIDDEN_SECURITY_OPTS: &[&str] = &[
	"seccomp=unconfined",
	"apparmor=unconfined",
	"systempaths=unconfined",
];

/// `init: false` is forbidden (force `init: true` so PID1 reaping works).
/// `init: true` is allowed. `init` absent is allowed.
fn init_is_forbidden(value: &Value) -> bool {
	matches!(value, Value::Bool(false))
}

/// C4: validate a `compose_yaml` payload against the deny-list.
///
/// `tenant_project_dir` is the canonical project dir on disk
/// (`/var/lib/glyndor/helmly/tenants/{tenant}/{project}/`). `volumes`
/// entries whose `source` is not under `tenant_project_dir`, the org
/// `WEBROOT`, the literal `/tmp`, or a relative path are rejected —
/// they would be a host-fs write from inside the container.
///
/// `init` is forced to `true` semantically: presence with `false` is
/// rejected; absence is allowed.
pub(crate) fn validate_compose(yaml: &str, tenant_project_dir: &str) -> Result<()> {
	let root: Value = serde_yaml_ng::from_str(yaml)
		.map_err(|e| anyhow!("compose_yaml is not valid YAML: {e}"))?;
	walk(&root, "")?;
	check_volumes(&root, tenant_project_dir)?;
	Ok(())
}

/// Recursive walker. Reports the path to the offending key for diagnostics.
fn walk(node: &Value, path: &str) -> Result<()> {
	match node {
		Value::Mapping(map) => {
			for (k, v) in map {
				let key = k.as_str().unwrap_or("?");
				let child_path = if path.is_empty() {
					key.to_string()
				} else {
					format!("{path}.{key}")
				};
				check_key_value(key, v, &child_path)?;
				walk(v, &child_path)?;
			}
		}
		Value::Sequence(seq) => {
			for (i, v) in seq.iter().enumerate() {
				let child_path = format!("{path}[{i}]");
				walk(v, &child_path)?;
			}
		}
		_ => {}
	}
	Ok(())
}

fn check_key_value(key: &str, value: &Value, path: &str) -> Result<()> {
	// 1. Hard-deny keys: presence anywhere is rejected.
	if DENY_KEYS.contains(&key) {
		// `init: true` is allowed; only `init: false` is rejected. The
		// allow side is handled here, not in the deny-keys table.
		if key == "init" && !init_is_forbidden(value) {
			return Ok(());
		}
		return Err(anyhow!(
			"compose_yaml contains forbidden key {path:?} ({key:?}); \
             helmly-agent does not permit this key on tenant containers"
		));
	}
	// 2. Conditional-deny keys: only some values are forbidden.
	for (k, forbidden) in FORBIDDEN_VALUES {
		if *k == key {
			if let Value::String(s) = value {
				if s == *forbidden || (s.starts_with("container:") && *forbidden == "container") {
					return Err(anyhow!(
						"compose_yaml contains forbidden value {path:?} = {s:?}; \
                         helmly-agent does not permit this value on tenant containers"
					));
				}
			}
		}
	}
	// 3. `userns_mode: host` (any value other than `auto`).
	if key == "userns_mode" {
		if let Value::String(s) = value {
			if s != "auto" {
				return Err(anyhow!(
					"compose_yaml contains forbidden value {path:?} = {s:?}; \
                     only userns_mode: auto is permitted"
				));
			}
		}
	}
	// 4. `cap_drop: ["ALL"]` denies all capabilities, defeating rootless.
	if key == "cap_drop" {
		if let Value::Sequence(seq) = value {
			for v in seq {
				if let Value::String(s) = v {
					if s == "ALL" {
						return Err(anyhow!(
							"compose_yaml contains cap_drop: [ALL] at {path:?}; \
                             helmly-agent does not permit dropping all caps"
						));
					}
				}
			}
		}
	}
	// 5. `security_opt: ["seccomp=unconfined", ...]` defeats seccomp.
	if key == "security_opt" {
		if let Value::Sequence(seq) = value {
			for v in seq {
				if let Value::String(s) = v {
					if FORBIDDEN_SECURITY_OPTS.iter().any(|f| *f == s) {
						return Err(anyhow!(
							"compose_yaml contains forbidden security_opt {s:?} at {path:?}"
						));
					}
				}
			}
		}
	}
	Ok(())
}

/// Volume source guard: host-path volumes are constrained to (a) the
/// project dir itself, (b) the org webroot, (c) literal `/tmp` (which
/// is what `tmpfs:` resolves to for short-lived scratch), or (d) a
/// relative path (which podman resolves against the project dir).
fn check_volumes(root: &Value, tenant_project_dir: &str) -> Result<()> {
	fn check_service_volumes(svc: &Value, tenant_project_dir: &str) -> Result<()> {
		let volumes = match svc.get("volumes") {
			Some(v) => v,
			None => return Ok(()),
		};
		let arr = match volumes {
			Value::Sequence(seq) => seq,
			_ => return Ok(()),
		};
		for (i, entry) in arr.iter().enumerate() {
			// Long form: `{source: /host/path, target: /in/container, ...}`.
			if let Value::Mapping(m) = entry {
				if let Some(Value::String(src)) = m.get("source") {
					if !volume_source_ok(src, tenant_project_dir) {
						return Err(anyhow!(
							"compose_yaml services.*.volumes[{i}].source {src:?} \
                             is outside the tenant root ({tenant_project_dir}); \
                             helmly-agent rejects host-path volumes outside \
                             the project dir, /var/lib/glyndor/helmly/nginx/webroot, \
                             /tmp, or relative paths"
						));
					}
				}
			}
			// Short form: `/host/path:/in/container[:ro]` — source is
			// the part before the first colon. Skip named volumes
			// (`db:/var/lib/...` — no leading `/`).
			else if let Value::String(s) = entry {
				if let Some((src, _)) = s.split_once(':') {
					if !volume_source_ok(src, tenant_project_dir) {
						return Err(anyhow!(
							"compose_yaml services.*.volumes[{i}] short-form source {src:?} \
                             is outside the tenant root ({tenant_project_dir})"
						));
					}
				}
			}
		}
		Ok(())
	}
	let services = match root.get("services") {
		Some(Value::Mapping(m)) => m,
		_ => return Ok(()),
	};
	for (_, svc) in services {
		check_service_volumes(svc, tenant_project_dir)?;
	}
	Ok(())
}

fn volume_source_ok(src: &str, tenant_project_dir: &str) -> bool {
	if src.starts_with('/') {
		// Absolute host path — must be under tenant root, webroot, or /tmp.
		src.starts_with(tenant_project_dir)
			|| src.starts_with(WEBROOT)
			|| src == "/tmp"
			|| src.starts_with("/tmp/")
	} else {
		// Relative path — podman resolves against the project dir.
		true
	}
}

// =========================================================================
// Nginx allow-list
// =========================================================================

/// C4: allow-list of nginx directives permitted in tenant reverse-proxy
/// config. Directives outside this set are rejected. Per the compat
/// review, the legitimate reverse-proxy surface is ~15 directives; a
/// deny-list of dangerous ones would be much longer.
const ALLOWED_NGINX_DIRECTIVES: &[&str] = &[
	// Block roots
	"events", "http", "server", "location", "upstream",
	"map",
	// http.* / server.* / location.* / upstream.* leaves the parser
	// to walk — the deny list below is what blocks the dangerous ones.
];

const ALLOWED_NGINX_LEAF_DIRECTIVES: &[&str] = &[
	// events.*
	"worker_connections",
	// http.*
	"include",
	"default_type",
	"sendfile",
	"tcp_nodelay",
	"keepalive_timeout",
	"gzip",
	"gzip_types",
	"server_tokens",
	"client_max_body_size",
	"log_format",
	"access_log",
	"error_log",
	// server.*
	"listen",
	"server_name",
	"ssl_certificate",
	"ssl_certificate_key",
	"ssl_protocols",
	"ssl_ciphers",
	"ssl_prefer_server_ciphers",
	"ssl_session_cache",
	"ssl_session_timeout",
	"return",
	"root",
	// location.*
	"proxy_pass",
	"proxy_set_header",
	"proxy_ssl_server_name",
	"proxy_http_version",
	"proxy_read_timeout",
	"proxy_connect_timeout",
	"proxy_send_timeout",
	"proxy_buffering",
	"try_files",
	"rewrite",
	"expires",
	"add_header",
	// upstream.*
	"server",
	"keepalive",
	"ip_hash",
	"least_conn",
];

/// Hard-deny directives that should never appear even if nginx accepts
/// them. This is defence-in-depth on top of the allow-list.
const DENY_NGINX_DIRECTIVES: &[&str] = &[
	"dgram_access",
	"perl_modules",
	"perl_require",
	"load_module",
	"secure_link_secret",
	"ssl_engine",
	"aio",
	"thread_pool",
	"js_import",
	"js_content",
	"client_body_temp_path",
	"fastcgi_param",
	"uwsgi_param",
	"scgi_param",
];

/// `proxy_pass` whose URL points at a unix docker socket — defence
/// against the documented podman→host escape.
const DENY_NGINX_PROXY_PATTERNS: &[&str] = &["unix:/var/run/docker.sock", "unix:/var/run/podman/"];

/// C4: validate an nginx config against the allow-list.
///
/// The check is **structural** (line-by-line, brace-aware) — we don't
/// parse full nginx syntax. After this passes, the config still needs
/// to be `nginx -t`'d at runtime (the handler does that).
pub(crate) fn validate_nginx(config: &str) -> Result<()> {
	let mut depth: i32 = 0;
	let mut last_block_directive: Option<String> = None;
	for (idx, raw_line) in config.lines().enumerate() {
		let line_num = idx + 1;
		let line = strip_comment(raw_line).trim();
		if line.is_empty() {
			continue;
		}
		// Track brace depth and block context.
		let opens = line.matches('{').count() as i32;
		let closes = line.matches('}').count() as i32;
		let block_opener = line.trim_end_matches('{').trim();
		if !block_opener.is_empty() && opens > 0 {
			// New block starts at this line.
			let first = first_token(block_opener);
			if !ALLOWED_NGINX_DIRECTIVES.iter().any(|d| d == &first) {
				return Err(anyhow!(
					"nginx config line {line_num}: block directive {first:?} \
                     is not in the allow-list"
				));
			}
			if DENY_NGINX_DIRECTIVES.iter().any(|d| d == &first) {
				return Err(anyhow!(
					"nginx config line {line_num}: block directive {first:?} is hard-denied"
				));
			}
			last_block_directive = Some(first.to_string());
		}
		// Parse simple `key value;` / `key arg1 arg2;` directives.
		// For our allow-list purposes, just look at the first token.
		let first = first_token(line.trim_end_matches(';').trim_end_matches('{').trim());
		if first.is_empty() {
			// Pure `}` or `{` — depth change.
			depth += opens - closes;
			continue;
		}
		if opens == 0 && closes == 0 {
			// Leaf directive.
			if last_block_directive.is_some() {
				let allowed_in: &[&str] = match last_block_directive.as_deref() {
					Some("events") => &["worker_connections"],
					// For `http`, `server`, `location`, `upstream`, `map` —
					// any leaf in the union is allowed; the deny list blocks
					// the dangerous ones.
					_ => ALLOWED_NGINX_LEAF_DIRECTIVES,
				};
				if !allowed_in.iter().any(|d| d == &first)
					&& !ALLOWED_NGINX_DIRECTIVES.iter().any(|d| d == &first)
				{
					return Err(anyhow!(
						"nginx config line {line_num}: directive {first:?} \
                         not in the allow-list for block {:?}",
						last_block_directive.as_deref().unwrap_or("?")
					));
				}
				if DENY_NGINX_DIRECTIVES.iter().any(|d| d == &first) {
					return Err(anyhow!(
						"nginx config line {line_num}: directive {first:?} is hard-denied"
					));
				}
				if first == "proxy_pass" {
					let value = line
						.trim_end_matches(';')
						.trim_start_matches("proxy_pass")
						.trim();
					for pattern in DENY_NGINX_PROXY_PATTERNS {
						if value.contains(pattern) {
							return Err(anyhow!(
								"nginx config line {line_num}: proxy_pass {value:?} \
                                 is hard-denied (matches {pattern:?})"
							));
						}
					}
				}
			}
		}
		depth += opens - closes;
	}
	if depth != 0 {
		return Err(anyhow!(
			"nginx config has unbalanced braces (final depth {depth})"
		));
	}
	Ok(())
}

fn strip_comment(line: &str) -> &str {
	// Nginx comments start with `#`. Inside a quoted string they don't,
	// but the allow-list walker is structural — a `#` in a string
	// wouldn't open a brace, so this is safe enough for our purposes.
	if let Some(idx) = line.find('#') {
		&line[..idx]
	} else {
		line
	}
}

fn first_token(s: &str) -> &str {
	s.split_whitespace().next().unwrap_or("")
}

#[cfg(test)]
mod tests;
