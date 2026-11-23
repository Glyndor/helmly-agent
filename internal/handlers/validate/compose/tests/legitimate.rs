//! Composes that must keep passing: the ones the repository already used in its
//! tests, ordinary multi-service projects, and for each refusal the value just
//! inside it.

use super::*;

const WEB_AND_DB: &str = r#"
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

const FULL_SERVICE: &str = r#"
x-logging: &logging
  driver: json-file
  options:
    max-size: "10m"
services:
  app:
    image: ghcr.io/example/app:1.2.3
    restart: unless-stopped
    init: true
    user: "1000:1000"
    working_dir: /app
    command: ["sh", "-c", "echo $$HOME && exec app"]
    entrypoint: /usr/bin/tini
    environment:
      - MODE=production
      - PRICE=$$5
    labels:
      com.example.team: web
    logging: *logging
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://localhost:3000/health || exit 1"]
      interval: 30s
      retries: 3
    read_only: true
    cap_drop: [NET_RAW, MKNOD]
    security_opt:
      - no-new-privileges:true
      - label=level:s0:c100,c200
      - apparmor=docker-default
      - mask=/proc/acpi
    userns_mode: auto
    network_mode: bridge
    pid: private
    ipc: shareable
    uts: private
    cgroup: private
    extra_hosts:
      - "api.example.com:203.0.113.10"
      - "v6.example.com=2001:db8::10"
    ports:
      - "8081:80"
      - "127.0.0.1:9091:9090"
      - "[::]:51821:51820/udp"
      - "3000"
      - 3001
      - "127.0.0.1::5432"
      - target: 443
        published: "8443"
        host_ip: 0.0.0.0
      - target: 8000
    deploy:
      resources:
        limits:
          cpus: "0.5"
          memory: 256M
    secrets:
      - db_password
      - source: api_key
        target: /run/secrets/api
    configs:
      - app_config
secrets:
  db_password:
    external: true
  api_key:
    external: true
configs:
  app_config:
    content: |
      key = value
"#;

const VOLUMES_UNDER_PROJECT: &str = r#"
services:
  web:
    image: nginx
    volumes:
      - ./data:/app/data
      - ./config:/app/config:ro
      - /var/lib/glyndor/helmly/projects/t1/p1/data:/data
      - /var/lib/glyndor/helmly/projects/t1/p1/etc/app.conf:/etc/app.conf:ro
      - /var/lib/glyndor/helmly/nginx/webroot:/usr/share/nginx/html:ro
      - /tmp:/scratch
      - /tmp/app:/scratch2
      - cache:/cache
      - /anonymous
      - type: bind
        source: ./uploads
        target: /uploads
      - type: bind
        source: logs
        target: /logs
      - type: volume
        source: cache
        target: /cache2
      - type: volume
        target: /anonymous2
volumes:
  cache:
  scratch:
    driver_opts:
      type: tmpfs
      device: tmpfs
      o: "size=100m,uid=1000"
"#;

const CASES: &[(&str, &str)] = &[
	("empty services, as the handler tests send", "services: {}\n"),
	("web and database", WEB_AND_DB),
	("service with most keys set to permitted values", FULL_SERVICE),
	("volumes under the project, webroot and /tmp", VOLUMES_UNDER_PROJECT),
	("network named like a service", "networks:\n  backend:\n    name: backend-net\n    driver: bridge\nservices:\n  web:\n    image: nginx\n    networks: [backend]\n"),
	("network mode none", "services:\n  web:\n    image: nginx\n    network_mode: none\n"),
	("bare pasta network mode", "services:\n  web:\n    image: nginx\n    network_mode: pasta\n"),
	("labels as a list", "services:\n  web:\n    image: nginx\n    labels: [\"com.example.role=web\"]\n"),
	("extra_hosts as a mapping", "services:\n  web:\n    image: nginx\n    extra_hosts:\n      api: 203.0.113.10\n      both: [\"203.0.113.11\", \"2001:db8::11\"]\n"),
	("core schema tag, resolved by the parser", "services:\n  web:\n    image: !!str nginx\n"),
	("top-level extension used as an alias", "x-image: &img nginx\nservices:\n  web:\n    image: *img\n"),
	("version key", "version: \"3.8\"\nservices:\n  web:\n    image: nginx\n"),
	("service named secrets", "services:\n  secrets:\n    image: vault\n    environment:\n      MODE: dev\n"),
	("escaped dollar only", "services:\n  web:\n    image: nginx\n    command: echo $$PATH\n"),
	("port just below the listener", "services:\n  web:\n    image: nginx\n    ports: [\"9089:80\"]\n"),
	("range that stops before the listener", "services:\n  web:\n    image: nginx\n    ports: [\"9000-9089:9000-9089\"]\n"),
];

#[test]
fn legitimate_composes_pass() {
	assert_accepted(CASES);
}
