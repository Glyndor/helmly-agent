//! `extra_hosts`: host name to address entries written into the container's
//! `/etc/hosts`. An address that leads back to the host (its loopback, the
//! runner's gateway alias, a link-local address) is refused.

use std::net::{IpAddr, Ipv4Addr};

use anyhow::{anyhow, Result};
use serde_yaml_ng::Value;

use super::expect_str;

/// The address slirp4netns gives the host inside the container.
const SLIRP_HOST: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);

/// Check every address in an `extra_hosts` value: a list of `host:addr` or
/// `host=addr` strings, or a map of host to an address or a list of them.
pub(super) fn check(value: &Value, path: &str) -> Result<()> {
	match value {
		Value::Sequence(seq) => {
			for (i, item) in seq.iter().enumerate() {
				let here = format!("{path}[{i}]");
				let entry = expect_str(item, &here)?;
				let split = entry.split_once('=').or_else(|| entry.split_once(':'));
				let Some((_, addr)) = split else {
					return Err(anyhow!(
						"compose_yaml {here:?} = {entry:?} is not `host:address`"
					));
				};
				check_addr(addr, &here)?;
			}
			Ok(())
		}
		Value::Mapping(map) => {
			for (host, addrs) in map {
				let here = super::child_path(path, host.as_str().unwrap_or_default());
				match addrs {
					Value::Sequence(seq) => {
						for (i, addr) in seq.iter().enumerate() {
							let item = format!("{here}[{i}]");
							check_addr(expect_str(addr, &item)?, &item)?;
						}
					}
					_ => check_addr(expect_str(addrs, &here)?, &here)?,
				}
			}
			Ok(())
		}
		_ => Err(anyhow!(
			"compose_yaml {path:?} must be a list or a mapping; helmly-agent refuses \
			 any other shape here"
		)),
	}
}

fn check_addr(raw: &str, path: &str) -> Result<()> {
	let addr = raw.trim();
	if addr.eq_ignore_ascii_case("host-gateway") {
		return Err(anyhow!(
			"compose_yaml {path:?} points at the host gateway; helmly-agent does not \
			 permit host aliases that lead back to the host"
		));
	}
	let bare = addr
		.strip_prefix('[')
		.and_then(|a| a.strip_suffix(']'))
		.unwrap_or(addr);
	let Ok(ip) = bare.parse::<IpAddr>() else {
		return Err(anyhow!(
			"compose_yaml {path:?} = {raw:?} is not an IP address; helmly-agent only \
			 accepts literal addresses in extra_hosts"
		));
	};
	if leads_to_host(ip) {
		return Err(anyhow!(
			"compose_yaml {path:?} = {raw:?} leads back to the host; helmly-agent does \
			 not permit loopback, unspecified, link-local or gateway addresses here"
		));
	}
	Ok(())
}

/// Loopback, unspecified and link-local addresses, and the slirp4netns host
/// address. Link-local covers the address pasta maps to the host
/// (169.254.1.2) and the cloud metadata service (169.254.169.254).
fn leads_to_host(ip: IpAddr) -> bool {
	match ip {
		IpAddr::V4(v4) => {
			v4.is_loopback() || v4.is_unspecified() || v4.is_link_local() || v4 == SLIRP_HOST
		}
		IpAddr::V6(v6) => {
			if let Some(v4) = v6.to_ipv4_mapped() {
				return leads_to_host(IpAddr::V4(v4));
			}
			v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80
		}
	}
}
