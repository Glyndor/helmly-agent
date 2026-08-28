use super::*;
use crate::auth::{PermissionLevel, VerifiedCommand};
use std::cell::RefCell;

/// The chain exactly as `setup-agent.sh:1204-1229` writes it on a
/// dashboard VPS, in `nft -a list chain` form. The accept for the setup
/// port sits ABOVE the chain's trailing drop, which is what made the old
/// implementation's appended drop unreachable.
fn chain_with_setup_port_open() -> String {
	"\
table inet helmly-agent {
	chain helmly-base {
		type filter hook input priority 0; policy drop;
		iif \"lo\" accept # handle 4
		ct state established,related accept # handle 5
		tcp dport 22 ct state new accept # handle 7
		udp dport 51820 accept # handle 8
		tcp dport 19443 ct state new accept # handle 9
		iifname \"wg0\" tcp dport 9090 accept # handle 11
		drop # handle 12
	}
}"
	.to_string()
}

fn chain_with_setup_port_closed() -> String {
	chain_with_setup_port_open()
		.lines()
		.filter(|l| !l.contains("dport 19443"))
		.collect::<Vec<_>>()
		.join("\n")
}

fn cmd(permission: PermissionLevel) -> VerifiedCommand {
	VerifiedCommand {
		user_id: uuid::Uuid::nil(),
		organization_id: None,
		permission,
		command: serde_json::json!({ "type": "nftables.close_setup_port" }),
	}
}

/// A fake `nft` that serves a listing, records every invocation, and
/// switches to the post-delete listing once a delete has been issued.
struct FakeNft {
	calls: RefCell<Vec<Vec<String>>>,
	deleted: RefCell<bool>,
	// When true, the second listing still shows the port open, standing in
	// for a delete that reported success without changing the ruleset.
	delete_is_a_lie: bool,
}

impl FakeNft {
	fn new(delete_is_a_lie: bool) -> Self {
		Self {
			calls: RefCell::new(Vec::new()),
			deleted: RefCell::new(false),
			delete_is_a_lie,
		}
	}
	fn run(&self, args: &[&str]) -> anyhow::Result<String> {
		self.calls
			.borrow_mut()
			.push(args.iter().map(|s| s.to_string()).collect());
		if args.first() == Some(&"delete") {
			*self.deleted.borrow_mut() = true;
			return Ok(String::new());
		}
		if *self.deleted.borrow() && !self.delete_is_a_lie {
			Ok(chain_with_setup_port_closed())
		} else {
			Ok(chain_with_setup_port_open())
		}
	}
}

#[test]
fn accepting_handles_finds_the_rule_that_holds_the_port_open() {
	assert_eq!(accepting_handles(&chain_with_setup_port_open()), vec![9]);
}

#[test]
fn accepting_handles_ignores_a_rule_that_drops_the_port() {
	// The old implementation's appended rule. It must not be mistaken for
	// something holding the port open, and deleting it would be wrong.
	let listing = "\t\ttcp dport 19443 drop # handle 40";
	assert!(accepting_handles(listing).is_empty());
}

#[test]
fn accepting_handles_ignores_a_line_that_merely_mentions_the_number() {
	let listing = "\t\tcomment \"see 19443 in the runbook\" # handle 41";
	assert!(accepting_handles(listing).is_empty());
}

#[test]
fn close_deletes_by_handle_rather_than_appending_a_drop() {
	let nft = FakeNft::new(false);
	let out =
		close_setup_port_with(&cmd(PermissionLevel::Write), &|a| nft.run(a)).expect("must close");
	assert_eq!(out["ok"], true);
	assert_eq!(out["rules_deleted"], 1);

	let calls = nft.calls.borrow();
	assert!(
		calls
			.iter()
			.any(|c| c[0] == "delete" && c.contains(&"9".to_string())),
		"must delete handle 9, the accepting rule; calls were {calls:?}"
	);
	assert!(
		!calls.iter().any(|c| c.contains(&"drop".to_string())),
		"must not append a drop; that is the bug being fixed"
	);
}

#[test]
fn close_re_reads_the_chain_and_refuses_to_report_success_when_the_port_is_still_open() {
	// The delete reports success and the ruleset does not change. Without
	// the re-read this returns {"ok": true} with the port open, which is
	// exactly what #149 was.
	let nft = FakeNft::new(true);
	let err = close_setup_port_with(&cmd(PermissionLevel::Write), &|a| nft.run(a))
		.expect_err("a port still accepted must not be reported closed");
	assert!(
		format!("{err:?}").contains("still accepted"),
		"the error must say what is wrong, got {err:?}"
	);
}

#[test]
fn close_requires_write_permission() {
	let nft = FakeNft::new(false);
	let err = close_setup_port_with(&cmd(PermissionLevel::Read), &|a| nft.run(a))
		.expect_err("Read must be refused");
	assert!(matches!(err, AgentError::Forbidden(_)));
	assert!(
		nft.calls.borrow().is_empty(),
		"the gate must run before nft is touched"
	);
}
