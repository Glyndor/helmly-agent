use super::*;

// ---- compose YAML tests ----

#[test]
fn compose_privileged_rejected() {
	let y = r#"
services:
  web:
    image: nginx
    privileged: true
"#;
	let r = validate_compose(y, "/var/lib/glyndor/helmly/tenants/t1/p1");
	assert!(r.is_err(), "privileged: true must be rejected");
	let msg = format!("{:#}", r.unwrap_err());
	assert!(msg.contains("forbidden key") && msg.contains("privileged"));
}

#[test]
fn compose_network_mode_host_rejected() {
	let y = r#"
services:
  web:
    image: nginx
    network_mode: host
"#;
	let r = validate_compose(y, "/var/lib/glyndor/helmly/tenants/t1/p1");
	assert!(r.is_err());
	let msg = format!("{:#}", r.unwrap_err());
	assert!(msg.contains("network_mode"));
}

#[test]
fn compose_cap_add_rejected() {
	let y = r#"
services:
  web:
    image: nginx
    cap_add: ["SYS_ADMIN"]
"#;
	let r = validate_compose(y, "/var/lib/glyndor/helmly/tenants/t1/p1");
	assert!(r.is_err());
	assert!(format!("{:#}", r.unwrap_err()).contains("cap_add"));
}

#[test]
fn compose_volume_outside_tenant_root_rejected() {
	let y = r#"
services:
  web:
    image: nginx
    volumes:
      - /:/host
"#;
	let r = validate_compose(y, "/var/lib/glyndor/helmly/tenants/t1/p1");
	assert!(r.is_err());
	let msg = format!("{:#}", r.unwrap_err());
	assert!(msg.contains("outside the tenant root"));
}

#[test]
fn compose_volume_long_form_long_path_rejected() {
	let y = r#"
services:
  web:
    image: nginx
    volumes:
      - source: /etc/passwd
        target: /in/container
"#;
	let r = validate_compose(y, "/var/lib/glyndor/helmly/tenants/t1/p1");
	assert!(r.is_err());
}

#[test]
fn compose_volume_relative_path_allowed() {
	let y = r#"
services:
  web:
    image: nginx
    volumes:
      - ./data:/app/data
      - ./config:/app/config:ro
"#;
	let r = validate_compose(y, "/var/lib/glyndor/helmly/tenants/t1/p1");
	assert!(r.is_ok(), "relative paths must pass: {r:?}");
}

#[test]
fn compose_volume_under_tenant_root_allowed() {
	let dir = "/var/lib/glyndor/helmly/tenants/t1/p1";
	let y = format!(
		r#"
services:
  web:
    image: nginx
    volumes:
      - {dir}/data:/data
      - {dir}/etc/app.conf:/etc/app.conf:ro
"#
	);
	let r = validate_compose(&y, dir);
	assert!(r.is_ok(), "in-tree volumes must pass: {r:?}");
}

#[test]
fn compose_volume_under_webroot_allowed() {
	let dir = "/var/lib/glyndor/helmly/tenants/t1/p1";
	let y = r#"
services:
  web:
    image: nginx
    volumes:
      - /var/lib/glyndor/helmly/nginx/webroot:/usr/share/nginx/html:ro
"#;
	let r = validate_compose(y, dir);
	assert!(r.is_ok(), "webroot mount must pass: {r:?}");
}

#[test]
fn compose_init_true_allowed() {
	let y = r#"
services:
  web:
    image: nginx
    init: true
"#;
	let r = validate_compose(y, "/var/lib/glyndor/helmly/tenants/t1/p1");
	assert!(r.is_ok(), "init: true must pass: {r:?}");
}

#[test]
fn compose_init_false_rejected() {
	let y = r#"
services:
  web:
    image: nginx
    init: false
"#;
	let r = validate_compose(y, "/var/lib/glyndor/helmly/tenants/t1/p1");
	assert!(r.is_err(), "init: false must be rejected");
}

#[test]
fn compose_security_opt_seccomp_unconfined_rejected() {
	let y = r#"
services:
  web:
    image: nginx
    security_opt:
      - seccomp=unconfined
"#;
	let r = validate_compose(y, "/var/lib/glyndor/helmly/tenants/t1/p1");
	assert!(r.is_err());
}

#[test]
fn compose_legitimate_service_passes() {
	let y = r#"
services:
  web:
    image: nginx
    ports:
      - "8080:80"
    environment:
      DB_HOST: db
    depends_on:
      - db
    volumes:
      - ./data:/app/data
    networks:
      - default
  db:
    image: postgres
    volumes:
      - dbdata:/var/lib/postgresql/data
    environment:
      POSTGRES_PASSWORD: secret
networks:
  default:
volumes:
  dbdata:
"#;
	let r = validate_compose(y, "/var/lib/glyndor/helmly/tenants/t1/p1");
	assert!(r.is_ok(), "legitimate compose must pass: {r:?}");
}

// ---- nginx tests ----

#[test]
fn nginx_dgram_access_rejected() {
	let c = r#"
http {
    server {
        listen 80;
        dgram_access unix:/var/run/foo.sock;
    }
}
"#;
	let r = validate_nginx(c);
	assert!(r.is_err());
}

#[test]
fn nginx_load_module_rejected() {
	let c = r#"
http {
    load_module foo;
    server {
        listen 80;
    }
}
"#;
	let r = validate_nginx(c);
	assert!(r.is_err());
}

#[test]
fn nginx_proxy_pass_unix_docker_socket_rejected() {
	let c = r#"
http {
    server {
        listen 80;
        location / {
            proxy_pass http://unix:/var/run/docker.sock:/;
        }
    }
}
"#;
	let r = validate_nginx(c);
	assert!(r.is_err());
}

#[test]
fn nginx_unknown_block_directive_rejected() {
	let c = r#"
http {
    stream {
        listen 80;
    }
}
"#;
	let r = validate_nginx(c);
	assert!(r.is_err(), "stream block must be rejected: {r:?}");
}

#[test]
fn nginx_unknown_leaf_directive_rejected() {
	let c = r#"
http {
    server {
        listen 80;
        perl_modules foo;
    }
}
"#;
	let r = validate_nginx(c);
	assert!(r.is_err());
}

#[test]
fn nginx_legitimate_reverse_proxy_passes() {
	let c = r#"
events {
    worker_connections 1024;
}
http {
    server {
        listen 80;
        listen 443 ssl;
        server_name example.com;
        ssl_certificate /etc/glyndor/helmly/nginx/certs/example.com/fullchain.pem;
        ssl_certificate_key /etc/glyndor/helmly/nginx/certs/example.com/privkey.pem;
        add_header Strict-Transport-Security "max-age=31536000" always;
        location / {
            proxy_pass http://app:3000;
            proxy_set_header Host $host;
            proxy_http_version 1.1;
        }
        location /static {
            root /var/lib/glyndor/helmly/nginx/webroot;
        }
    }
}
"#;
	let r = validate_nginx(c);
	assert!(r.is_ok(), "legitimate reverse-proxy must pass: {r:?}");
}
