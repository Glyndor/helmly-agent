//! `extra_hosts` entries that point a name back at the host.

use super::*;

const BACK: &str = "leads back to the host";

const CASES: &[Hostile] = &[
	("loopback, colon form", "services:\n  web:\n    image: nginx\n    extra_hosts: [\"h:127.0.0.1\"]\n", BACK),
	("loopback range", "services:\n  web:\n    image: nginx\n    extra_hosts: [\"h:127.1.2.3\"]\n", BACK),
	("IPv6 loopback, equals form", "services:\n  web:\n    image: nginx\n    extra_hosts: [\"h=::1\"]\n", BACK),
	("IPv6 loopback, colon form", "services:\n  web:\n    image: nginx\n    extra_hosts: [\"h:::1\"]\n", BACK),
	("bracketed IPv6 loopback", "services:\n  web:\n    image: nginx\n    extra_hosts: [\"h=[::1]\"]\n", BACK),
	("IPv4-mapped loopback", "services:\n  web:\n    image: nginx\n    extra_hosts: [\"h=::ffff:127.0.0.1\"]\n", BACK),
	("unspecified", "services:\n  web:\n    image: nginx\n    extra_hosts: [\"h:0.0.0.0\"]\n", BACK),
	("slirp4netns host address", "services:\n  web:\n    image: nginx\n    extra_hosts: [\"h:10.0.2.2\"]\n", BACK),
	("pasta host address", "services:\n  web:\n    image: nginx\n    extra_hosts: [\"h:169.254.1.2\"]\n", BACK),
	("metadata service", "services:\n  web:\n    image: nginx\n    extra_hosts: [\"m:169.254.169.254\"]\n", BACK),
	("IPv6 link-local", "services:\n  web:\n    image: nginx\n    extra_hosts: [\"h=fe80::1\"]\n", BACK),
	("loopback, mapping form", "services:\n  web:\n    image: nginx\n    extra_hosts:\n      h: 127.0.0.1\n", BACK),
	("loopback in a mapping list", "services:\n  web:\n    image: nginx\n    extra_hosts:\n      h: [\"203.0.113.7\", \"127.0.0.1\"]\n", BACK),
	("host-gateway", "services:\n  web:\n    image: nginx\n    extra_hosts: [\"h:host-gateway\"]\n", "host gateway"),
	("host-gateway, mapping form", "services:\n  web:\n    image: nginx\n    extra_hosts:\n      h: host-gateway\n", "host gateway"),
	("a name instead of an address", "services:\n  web:\n    image: nginx\n    extra_hosts: [\"h:localhost\"]\n", "not an IP address"),
	("no separator", "services:\n  web:\n    image: nginx\n    extra_hosts: [\"localhost\"]\n", "is not `host:address`"),
];

#[test]
fn host_aliases_back_to_the_host_are_refused() {
	assert_refused(CASES);
}
