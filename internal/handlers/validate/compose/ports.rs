//! `ports`: the host ports a service publishes. Publishing on a port
//! helmly-agent itself listens on is refused. Anything else stays permitted, including
//! publishing on every host interface.

use std::ops::RangeInclusive;

use anyhow::{anyhow, Result};
use serde_yaml_ng::Value;

use super::{expect_seq, expect_str};

/// Check every entry of a `ports` list against `reserved`.
///
/// Short form: `[[host_ip:]published:]target[/protocol]`, where `published`
/// may be a range and `host_ip` may be bracketed IPv6. Long form: a map whose
/// `published` is a port or a range. A bare container port, or an empty
/// `published`, lets the runtime pick a free host port and is accepted.
pub(super) fn check(value: &Value, path: &str, reserved: &[u16]) -> Result<()> {
	for (i, entry) in expect_seq(value, path)?.iter().enumerate() {
		let here = format!("{path}[{i}]");
		let published = match entry {
			Value::Number(_) => None,
			Value::String(s) => short_form_published(s),
			Value::Mapping(m) => match m.get("published") {
				None | Some(Value::Null) => None,
				Some(Value::Number(n)) => Some(n.to_string()),
				Some(v) => Some(expect_str(v, &format!("{here}.published"))?.to_string()),
			},
			_ => {
				return Err(anyhow!(
					"compose_yaml {here:?} must be a port, a string or a mapping; \
					 helmly-agent refuses any other shape here"
				));
			}
		};
		let Some(published) = published.filter(|p| !p.trim().is_empty()) else {
			continue;
		};
		let range = parse_range(&published).ok_or_else(|| {
			anyhow!("compose_yaml {here:?} has a published port {published:?} that is not a port or a range")
		})?;
		if let Some(port) = reserved.iter().find(|p| range.contains(p)) {
			return Err(anyhow!(
				"compose_yaml {here:?} publishes host port {port}, which helmly-agent \
				 itself uses; pick another port"
			));
		}
	}
	Ok(())
}

/// The published part of a short-form entry, `None` when the entry names only
/// the container port.
fn short_form_published(entry: &str) -> Option<String> {
	let spec = entry.trim();
	let spec = spec.rsplit_once('/').map_or(spec, |(s, _)| s);
	// From the right: target, then published, then whatever address is left,
	// colons and brackets of an IPv6 address included.
	let mut parts = spec.rsplitn(3, ':');
	let _target = parts.next();
	parts.next().map(str::to_string)
}

/// `"8080"` or `"8000-8010"`.
fn parse_range(text: &str) -> Option<RangeInclusive<u16>> {
	let text = text.trim();
	let (lo, hi) = text.split_once('-').unwrap_or((text, text));
	let lo: u16 = lo.trim().parse().ok()?;
	let hi: u16 = hi.trim().parse().ok()?;
	(lo <= hi).then_some(lo..=hi)
}
