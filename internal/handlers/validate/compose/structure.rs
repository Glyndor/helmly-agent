//! Constructs that make the runner read something other than what the rest of
//! the validator reads. They are refused anywhere in the document, before any
//! key rule runs, so the key rules can assume plain strings, lists and maps.

use anyhow::{anyhow, Result};
use serde_yaml_ng::Value;

use super::child_path;

/// Refuse YAML tags, non-string keys, merge keys and interpolation anywhere
/// under `node`. `path` is the location of `node`, empty for the root.
///
/// Tags are refused because a runner strips them and applies the inner value,
/// while no rule here matches a tagged node. The core-schema tags (`!!str` and
/// the like) never reach this point: the parser resolves them to plain values.
/// Merge keys (`<<`) are refused because the parser keeps them as a literal key
/// while the runner merges them into the surrounding map, so a rule that looks
/// a key up in that map would not see what the merge brings in. Duplicate keys
/// need no rule: the parser already rejects them at any depth.
pub(super) fn check(node: &Value, path: &str) -> Result<()> {
	match node {
		Value::Tagged(tagged) => Err(anyhow!(
			"compose_yaml uses the YAML tag {} at {path:?}; helmly-agent does not \
			 permit tags in tenant compose files",
			tagged.tag
		)),
		Value::Mapping(map) => {
			for (k, v) in map {
				let key = match k {
					Value::String(s) => s.as_str(),
					Value::Tagged(tagged) => {
						return Err(anyhow!(
							"compose_yaml uses the YAML tag {} on a key under {path:?}; \
							 helmly-agent does not permit tags in tenant compose files",
							tagged.tag
						));
					}
					_ => {
						return Err(anyhow!(
							"compose_yaml has a key that is not a string under {path:?}; \
							 helmly-agent only accepts string keys"
						));
					}
				};
				let here = child_path(path, key);
				if key == "<<" {
					return Err(anyhow!(
						"compose_yaml uses a merge key at {here:?}; helmly-agent does not \
						 permit merge keys in tenant compose files"
					));
				}
				check_interpolation(key, &here)?;
				check(v, &here)?;
			}
			Ok(())
		}
		Value::Sequence(seq) => {
			for (i, v) in seq.iter().enumerate() {
				check(v, &format!("{path}[{i}]"))?;
			}
			Ok(())
		}
		Value::String(s) => check_interpolation(s, path),
		Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
	}
}

/// Refuse an unescaped `$` in `text`. The runner substitutes `$VAR` and
/// `${VAR}` from its own environment after this check has run, so no rule can
/// know the value it would be judging. `$$` is the escape for a literal `$` and
/// is accepted. A lone `$` followed by anything else is refused too: runners
/// disagree on whether it is literal or an error.
fn check_interpolation(text: &str, path: &str) -> Result<()> {
	let bytes = text.as_bytes();
	let mut i = 0;
	while i < bytes.len() {
		if bytes[i] == b'$' {
			if bytes.get(i + 1) == Some(&b'$') {
				i += 2;
				continue;
			}
			return Err(anyhow!(
				"compose_yaml has an unescaped `$` at {path:?}; helmly-agent does not \
				 permit variable interpolation in tenant compose files (write `$$` for \
				 a literal `$`)"
			));
		}
		i += 1;
	}
	Ok(())
}
