//! Namespace sharing with the host or another container, network mode options,
//! and the share of another container's volumes.

use super::*;

const SHARED: &str = "sharing a namespace";

const CASES: &[Hostile] = &[
	(
		"host network",
		r#"
services:
  web:
    image: nginx
    network_mode: host
"#,
		SHARED,
	),
	(
		"host network in capitals",
		r#"
services:
  web:
    image: nginx
    network_mode: HOST
"#,
		SHARED,
	),
	(
		"host pid",
		r#"
services:
  web:
    image: nginx
    pid: host
"#,
		SHARED,
	),
	(
		"host ipc",
		r#"
services:
  web:
    image: nginx
    ipc: host
"#,
		SHARED,
	),
	(
		"host uts",
		r#"
services:
  web:
    image: nginx
    uts: host
"#,
		SHARED,
	),
	(
		"host cgroup namespace",
		r#"
services:
  web:
    image: nginx
    cgroup: host
"#,
		SHARED,
	),
	(
		"network of another container",
		r#"
services:
  web:
    image: nginx
    network_mode: container:other
"#,
		SHARED,
	),
	(
		"pid of another container",
		r#"
services:
  web:
    image: nginx
    pid: container:other
"#,
		SHARED,
	),
	(
		"ipc of another service",
		r#"
services:
  web:
    image: nginx
    ipc: service:db
  db:
    image: postgres
"#,
		SHARED,
	),
	(
		"network of another service",
		r#"
services:
  web:
    image: nginx
    network_mode: service:db
  db:
    image: postgres
"#,
		SHARED,
	),
	(
		"pid namespace by path",
		r#"
services:
  web:
    image: nginx
    pid: ns:/proc/1/ns/pid
"#,
		SHARED,
	),
	(
		"slirp4netns with host loopback",
		r#"
services:
  web:
    image: nginx
    network_mode: slirp4netns:allow_host_loopback=true
"#,
		"network mode options",
	),
	(
		"pasta with options",
		r#"
services:
  web:
    image: nginx
    network_mode: pasta:--map-host-loopback,169.254.1.2
"#,
		"network mode options",
	),
	(
		"userns other than auto",
		r#"
services:
  web:
    image: nginx
    userns_mode: host
"#,
		"only userns_mode: auto",
	),
	(
		"volumes of another service",
		r#"
services:
  web:
    image: nginx
    volumes_from: [db]
  db:
    image: postgres
"#,
		"forbidden key \"services.web.volumes_from\"",
	),
	(
		"external network named host",
		r#"
networks:
  h:
    external: true
    name: host
services:
  web:
    image: nginx
    networks: [h]
"#,
		"the host network",
	),
	(
		"network with the host driver",
		r#"
networks:
  h:
    driver: host
services:
  web:
    image: nginx
    networks: [h]
"#,
		"the host network",
	),
];

#[test]
fn shared_namespaces_are_refused() {
	assert_refused(CASES);
}
