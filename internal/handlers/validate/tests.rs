use super::*;

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
