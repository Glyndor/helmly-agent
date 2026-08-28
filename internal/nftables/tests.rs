use super::*;

// --- render_ruleset — pure string generation, no I/O ---

fn minimal_ruleset() -> Ruleset {
	Ruleset {
		wireguard_port: 51820,
		dashboard_port: None,
		dashboard_wg_ip: None,
		org_networks: vec![],
		global_body: String::new(),
		local_body: String::new(),
		global_output_body: String::new(),
		local_output_body: String::new(),
	}
}

#[test]
fn render_contains_table_name() {
	let r = minimal_ruleset();
	let out = render_ruleset(&r);
	assert!(
		out.contains("table inet helmly-agent"),
		"table declaration missing"
	);
}

#[test]
fn render_contains_wireguard_port() {
	let r = minimal_ruleset();
	let out = render_ruleset(&r);
	assert!(out.contains("51820"), "WireGuard port missing from ruleset");
}

#[test]
fn render_wg_source_ip_restriction() {
	// Remote agent with dashboard_wg_ip set → WG rule must restrict source IP.
	let mut r = minimal_ruleset();
	r.dashboard_wg_ip = Some("10.100.0.1".to_string());
	let out = render_ruleset(&r);
	assert!(
		out.contains("ip saddr 10.100.0.1"),
		"WG source IP restriction missing on remote agent"
	);

	// Dashboard VPS (dashboard_port set) → WG rule must NOT restrict source IP.
	let mut r_dash = minimal_ruleset();
	r_dash.dashboard_port = Some(19443);
	r_dash.dashboard_wg_ip = Some("10.100.0.1".to_string());
	let out_dash = render_ruleset(&r_dash);
	// Source IP restriction must not appear on dashboard VPS WG rule
	// (agents connect from many different IPs)
	let wg_lines: Vec<&str> = out_dash.lines().filter(|l| l.contains("51820")).collect();
	assert!(
		wg_lines.iter().all(|l| !l.contains("ip saddr")),
		"dashboard VPS must not restrict WG source IP: {:?}",
		wg_lines
	);

	// Remote agent without dashboard_wg_ip → fall back to unrestricted
	let r_no_ip = minimal_ruleset();
	let out_no_ip = render_ruleset(&r_no_ip);
	assert!(
		out_no_ip.contains("udp dport 51820"),
		"WG rule must be present even without dashboard_wg_ip"
	);
}

#[test]
fn render_custom_wireguard_port() {
	let mut r = minimal_ruleset();
	r.wireguard_port = 12345;
	let out = render_ruleset(&r);
	assert!(out.contains("12345"), "custom WireGuard port not rendered");
}

#[test]
fn render_contains_helmly_base_chain() {
	let r = minimal_ruleset();
	let out = render_ruleset(&r);
	assert!(
		out.contains("chain helmly-base"),
		"helmly-base chain missing"
	);
}

#[test]
fn render_contains_helmly_global_chain() {
	let r = minimal_ruleset();
	let out = render_ruleset(&r);
	assert!(
		out.contains("chain helmly-global"),
		"helmly-global chain missing"
	);
}

#[test]
fn render_contains_helmly_local_chain() {
	let r = minimal_ruleset();
	let out = render_ruleset(&r);
	assert!(
		out.contains("chain helmly-local"),
		"helmly-local chain missing"
	);
}

#[test]
fn render_contains_helmly_forward_chain() {
	let r = minimal_ruleset();
	let out = render_ruleset(&r);
	assert!(
		out.contains("chain helmly-forward"),
		"helmly-forward chain missing"
	);
}

#[test]
fn render_contains_helmly_output_chain() {
	let r = minimal_ruleset();
	let out = render_ruleset(&r);
	assert!(
		out.contains("chain helmly-output"),
		"helmly-output chain missing"
	);
}

#[test]
fn render_contains_default_deny() {
	let r = minimal_ruleset();
	let out = render_ruleset(&r);
	assert!(out.contains("policy drop"), "default deny policy missing");
}

#[test]
fn render_contains_dashboard_management_ip() {
	// Management plane rules only render when dashboard_port is set (dashboard VPS).
	let mut r = minimal_ruleset();
	r.dashboard_port = Some(19443);
	let out = render_ruleset(&r);
	assert!(
		out.contains("10.100.0.1"),
		"dashboard management IP missing when dashboard_port set"
	);
	assert!(
		out.contains("10.100.0.0/16"),
		"agent subnet missing from management plane rules"
	);
	// Without dashboard_port, management plane rules must not appear.
	let r_agent = minimal_ruleset();
	let out_agent = render_ruleset(&r_agent);
	assert!(
		!out_agent.contains("10.100.0.0/16"),
		"management plane rules must not render on remote agent"
	);
}

#[test]
fn render_global_body_included() {
	let mut r = minimal_ruleset();
	r.global_body = "        tcp dport 443 accept".to_string();
	let out = render_ruleset(&r);
	assert!(
		out.contains("tcp dport 443 accept"),
		"global_body not included"
	);
}

#[test]
fn render_local_body_included() {
	let mut r = minimal_ruleset();
	r.local_body = "        tcp dport 8080 accept".to_string();
	let out = render_ruleset(&r);
	assert!(
		out.contains("tcp dport 8080 accept"),
		"local_body not included"
	);
}

#[test]
fn render_org_isolation_rules_included() {
	let mut r = minimal_ruleset();
	r.org_networks = vec![OrgNetwork {
		org_id: "org-abc".to_string(),
		subnet: "172.20.0.0/24".to_string(),
	}];
	let out = render_ruleset(&r);
	assert!(
		out.contains("172.20.0.0/24"),
		"org subnet missing from isolation rules"
	);
	assert!(
		out.contains("org-abc"),
		"org id missing from isolation comment"
	);
}

#[test]
fn render_multiple_orgs_all_present() {
	let mut r = minimal_ruleset();
	r.org_networks = vec![
		OrgNetwork {
			org_id: "org-1".to_string(),
			subnet: "172.20.1.0/24".to_string(),
		},
		OrgNetwork {
			org_id: "org-2".to_string(),
			subnet: "172.20.2.0/24".to_string(),
		},
	];
	let out = render_ruleset(&r);
	assert!(out.contains("172.20.1.0/24"));
	assert!(out.contains("172.20.2.0/24"));
}

#[test]
fn render_output_is_non_empty() {
	let r = minimal_ruleset();
	let out = render_ruleset(&r);
	assert!(!out.is_empty(), "rendered ruleset should not be empty");
}

#[test]
fn render_has_destroy_add_prefix() {
	let r = minimal_ruleset();
	let out = render_ruleset(&r);
	assert!(
		out.contains("destroy table inet helmly-agent"),
		"idempotent prefix missing: destroy table"
	);
	assert!(
		out.contains("add table inet helmly-agent"),
		"idempotent prefix missing: add table"
	);
}

#[test]
fn render_helmly_base_contains_ssh() {
	let r = minimal_ruleset();
	let out = render_ruleset(&r);
	assert!(
		out.contains("tcp dport 22"),
		"SSH accept missing from helmly-base"
	);
	assert!(
		out.contains("ssh_throttle"),
		"SSH rate-limit meter missing from helmly-base"
	);
}

#[test]
fn render_helmly_base_contains_icmp() {
	let r = minimal_ruleset();
	let out = render_ruleset(&r);
	assert!(
		out.contains("ip protocol icmp accept"),
		"ICMP v4 accept missing from helmly-base"
	);
	assert!(
		out.contains("ip6 nexthdr icmpv6 accept"),
		"ICMP v6 accept missing from helmly-base"
	);
}

#[test]
fn render_dashboard_port_included_when_set() {
	let mut r = minimal_ruleset();
	r.dashboard_port = Some(19443);
	let out = render_ruleset(&r);
	assert!(
		out.contains("tcp dport 19443"),
		"dashboard port not included when Some"
	);
}

#[test]
fn render_dashboard_port_absent_when_none() {
	let r = minimal_ruleset();
	let out = render_ruleset(&r);
	assert!(
		!out.contains("19443"),
		"dashboard port should not appear when None"
	);
}

#[test]
fn render_dashboard_dns_included_when_set() {
	let mut r = minimal_ruleset();
	r.dashboard_port = Some(19443);
	let out = render_ruleset(&r);
	assert!(
		out.contains("iifname \"podman*\" udp dport 53 accept"),
		"container DNS UDP missing when dashboard_port set"
	);
	assert!(
		out.contains("iifname \"podman*\" tcp dport 53 accept"),
		"container DNS TCP missing when dashboard_port set"
	);
}

#[test]
fn render_dashboard_dns_absent_when_none() {
	let r = minimal_ruleset();
	let out = render_ruleset(&r);
	assert!(
		!out.contains("udp dport 53"),
		"container DNS should not appear when dashboard_port is None"
	);
}

#[test]
fn render_dashboard_forward_rules_included_when_set() {
	let mut r = minimal_ruleset();
	r.dashboard_port = Some(19443);
	let out = render_ruleset(&r);
	assert!(
		out.contains("ip daddr 10.89.0.0/16 ct state new accept"),
		"Netavark published port forward rule missing when dashboard_port set"
	);
	assert!(
		out.contains("iifname \"podman*\" accept"),
		"container outbound forward rule missing when dashboard_port set"
	);
	assert!(
		out.contains("oifname \"wg-helmly-dash\" accept"),
		"WireGuard outbound forward rule missing when dashboard_port set"
	);
	assert!(
		out.contains("iifname \"wg-helmly-dash\" accept"),
		"WireGuard inbound forward rule missing when dashboard_port set"
	);
}

#[test]
fn render_dashboard_wg_forward_rules_absent_when_none() {
	let r = minimal_ruleset();
	let out = render_ruleset(&r);
	assert!(
		!out.contains("wg-helmly-dash"),
		"WireGuard forward rules should not appear when dashboard_port is None"
	);
}

#[test]
fn render_container_forward_rules_always_present() {
	// These rules are required on ALL agents (not just dashboard VPS) because
	// the agent's own PostgreSQL container is published via Netavark DNAT.
	let r = minimal_ruleset();
	let out = render_ruleset(&r);
	assert!(
		out.contains("ip daddr 10.89.0.0/16 ct state new accept"),
		"Netavark forward rule must be present on all agents"
	);
	assert!(
		out.contains("iifname \"podman*\" accept"),
		"Podman outbound forward rule must be present on all agents"
	);
}

// --- Emergency ruleset constant ---

#[test]
fn emergency_ruleset_is_non_empty() {
	assert!(!EMERGENCY_RULESET.is_empty());
	assert!(EMERGENCY_RULESET.contains("policy drop"));
	assert!(EMERGENCY_RULESET.contains("51820"));
	assert!(EMERGENCY_RULESET.contains("helmly-agent"));
}

#[test]
fn emergency_ruleset_has_destroy_add_prefix() {
	assert!(EMERGENCY_RULESET.contains("destroy table inet helmly-agent"));
	assert!(EMERGENCY_RULESET.contains("add table inet helmly-agent"));
}
