//! Publishing on a host port helmly-agent itself uses. Publishing on every host
//! interface is still permitted; see the legitimate corpus.

use super::*;

const OWN: &str = "which helmly-agent itself uses";

const CASES: &[Hostile] = &[
	("listener port", "services:\n  web:\n    image: nginx\n    ports: [\"9090:80\"]\n", OWN),
	("listener port on all interfaces", "services:\n  web:\n    image: nginx\n    ports: [\"0.0.0.0:9090:80\"]\n", OWN),
	("WireGuard port over UDP", "services:\n  web:\n    image: nginx\n    ports: [\"51820:51820/udp\"]\n", OWN),
	("setup port", "services:\n  web:\n    image: nginx\n    ports: [\"19443:443\"]\n", OWN),
	("bracketed IPv6 address", "services:\n  web:\n    image: nginx\n    ports: [\"[::]:9090:80\"]\n", OWN),
	("raw IPv6 address", "services:\n  web:\n    image: nginx\n    ports: [\"::1:9090:80\"]\n", OWN),
	("range that covers the listener", "services:\n  web:\n    image: nginx\n    ports: [\"9000-9100:9000-9100\"]\n", OWN),
	("long form, number", "services:\n  web:\n    image: nginx\n    ports:\n      - target: 80\n        published: 9090\n", OWN),
	("long form, string", "services:\n  web:\n    image: nginx\n    ports:\n      - target: 80\n        published: \"51820\"\n        protocol: udp\n", OWN),
	("long form, range", "services:\n  web:\n    image: nginx\n    ports:\n      - target: 80\n        published: \"19000-20000\"\n", OWN),
	(
		"published port that is not a number",
		"services:\n  web:\n    image: nginx\n    ports: [\"http:80\"]\n",
		"not a port or a range",
	),
	(
		"reversed range",
		"services:\n  web:\n    image: nginx\n    ports: [\"9100-9000:80\"]\n",
		"not a port or a range",
	),
];

#[test]
fn publishing_on_reserved_ports_is_refused() {
	assert_refused(CASES);
}
