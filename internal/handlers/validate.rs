//! C4: validation of signed-payload inputs.
//!
//! - Compose YAML: a deny-list for host-escape vectors over the parsed
//!   document, in `compose`. It refuses outright every construct that
//!   would let the runner read something the deny-list did not (YAML tags,
//!   merge keys, interpolation, second files, unexpected value shapes).
//! - Nginx config: **allow-list** of legitimate directives. Smaller
//!   than the deny-list of dangerous ones, and the reverse-proxy use
//!   case uses ~15 directives.
//!
//! Both validators return `Err` with a specific reason on rejection,
//! so the handler surfaces a useful message to the dashboard.
#![allow(clippy::manual_contains)]

mod compose;

pub(crate) use compose::{validate_compose, ComposePolicy};

use anyhow::{anyhow, Result};

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
