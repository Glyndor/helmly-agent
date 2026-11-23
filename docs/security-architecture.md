# helmly-agent security architecture

This document is the threat-model reference for the helmly-agent code on
this branch (`docs/security-architecture.md`). It is what the seven
security review agents (command-exec, firewall, transport, self-update,
container-isolation, audit-integrity, webserver) diff against.

Every claim about a control cites the file and the function, constant or
type that implements it, in the form `internal/auth/mod.rs::verify_command`.
No line number is used, because one goes stale with the first change above
it; `tests/docs/citations.test.sh` fails when a cited file or name no longer
exists. A control described here but not
present in the code belongs in the **Known gaps** section, not here.
Aspirations are not controls, and an entry in this document is what a
review agent would otherwise diff against, so a false entry launders a
gap into a passing review.

## 1. Scope and audience

`helmly-agent` is a privileged executor that runs as root on a managed
host (the "agent" or "agent server"). It is installed and commanded by
the `helmly` dashboard over a WireGuard tunnel and an Ed25519-signed
command surface. Its job is to mutate the host it sits on: the
nftables ruleset, system services (WireGuard, systemd, Podman, the
package manager), the local PostgreSQL store, and rootless tenant
containers managed through Podman.

This document covers the agent only. The dashboard's own security,
including its own authentication, its mTLS client to the agent, and
its session MFA, lives in the `helmly` repository, not here. The
one area where the two overlap is the wire format of the signed
command envelope, which is shared and is described here as observed by
the agent.

## 2. Assets

What an attacker with various foothold levels is after:

- **Root on the managed host.** The agent runs as root, owns the
  Podman setup for tenant workloads, and can call `systemctl reboot`,
  `useradd`, and `usermod`. Compromise of the agent is full compromise
  of the host.
- **Tenant containers and the data inside them.** The agent deploys
  Podman workloads on behalf of organisations and projects, and holds
  the per-tenant subuid range that isolates them.
- **The WireGuard tunnel to the dashboard.** The PSK (`internal/handlers/wireguard.rs`)
  and the per-peer public key live on the agent; their disclosure lets
  an attacker re-establish the management plane on their own host and
  impersonate the agent to the dashboard.
- **The audit trail's integrity.** The dashboard reconstructs an
  ordered, tamper-evident history of what the agent did. Breaking the
  chain is what hides a compromise after the fact.
- **The agent's credentials.** Three credentials matter:
  - `INTERNAL_TOKEN` (HTTP bearer, in
    `/etc/glyndor/helmly/credentials/internal-token`, served to the
    process by systemd `LoadCredential`, see the unit written by
    `setup-agent.sh::helmly-agent.service`).
  - `SYNC_TOKEN` (WebSocket + audit-sync bearer, same credential
    pattern).
  - The PostgreSQL password for the `helmly_agent_app` role (also
    `LoadCredential`-served, `/etc/glyndor/helmly/credentials/database-url`).
- **Through them, lateral movement.** A leaked `INTERNAL_TOKEN` does
  not give dashboard access on its own (the dashboard listens on the
  WireGuard interface, not on the agent), but combined with control
  of a peer on the management WireGuard subnet it does.

## 3. Trust boundaries

Each boundary names what crosses it, what authenticates it, and what
happens on failure.

### 3.1 Dashboard to agent (HTTP `/cmd`, `/heartbeat`; signed command stream over WebSocket)

What crosses: JSON `SignedCommand` envelopes
(`internal/auth/mod.rs::SignedCommand`), with the payload bytes base64url-encoded
and the Ed25519 signature over those bytes. The HTTP route also
carries an `Authorization: Bearer <INTERNAL_TOKEN>` header
(`internal/handlers/system.rs::execute_command`). On the WebSocket the bearer
is the `SYNC_TOKEN` carried as a query parameter on the upgrade URL
(`internal/ws_client.rs::run_ws_client`).

What authenticates: Ed25519 signature against a keyring
(`internal/auth/mod.rs::verify_command`), then nonce dedup against the
`used_nonces` table (`internal/auth/mod.rs::check_and_consume_nonce`), then
timestamp freshness against a 30s window
(`internal/auth/mod.rs::verify_command`), then `agent_id` match
(`internal/auth/mod.rs::verify_command`). The HTTP listener additionally
requires the bearer to match `INTERNAL_TOKEN`. The `/heartbeat` route
requires a valid Ed25519 signature, not the bearer, so a compromised
`INTERNAL_TOKEN` cannot suppress lockdown by faking heartbeats
(`internal/main.rs::heartbeat_handler`).

What happens on failure: rejection short-circuits to a 401/403/400 with
a redacted code (`internal/error.rs::AgentError`), the command is not
dispatched, and an audit row with `result = rejected` is appended
(`internal/handlers/system.rs::run_verified_command`).

### 3.2 Agent to dashboard (audit sync, telemetry, command responses, divergence events)

What crosses: a WebSocket carrying heartbeats, system metrics, container
metrics, and command responses (`internal/ws_client.rs::run_session`); a
periodic HTTP `POST /agents/<id>/audit-sync` carrying up to 100 audit
entries per batch (`internal/sync/mod.rs::run_sync_task`); a best-effort
HTTP `POST /agents/<id>/events` for nftables divergence notifications
(`internal/nftables/divergence.rs::notify_dashboard`).

What authenticates: the WebSocket upgrade carries `SYNC_TOKEN` as a
URL parameter (`internal/ws_client.rs::run_ws_client`); both HTTP POSTs carry
`Authorization: Bearer <SYNC_TOKEN>` (`internal/sync/mod.rs::sync_batch`,
`internal/nftables/divergence.rs::notify_dashboard`).

What happens on failure: the WebSocket reconnects with exponential
backoff capped at 300s (`internal/ws_client.rs::BACKOFF_BASE`, `internal/ws_client.rs::run_ws_client`); audit sync
errors are logged and retried on the next 60s tick
(`internal/sync/mod.rs::run_sync_task`); a 422 from the dashboard indicating
hash-chain mismatch resets the sync cursor to epoch and resends from
genesis (`internal/sync/mod.rs::sync_batch`).

### 3.3 Agent to host (nftables, systemd, WireGuard, the package manager)

What crosses: shell-outs to `nft` (`internal/nftables/mod.rs::run_nft`),
`wg` / `wg-quick` (`internal/handlers/wireguard.rs::handle_wg_rotate_psk`, `internal/handlers/wireguard.rs::handle_wg_data_plane_setup`),
`systemctl` (`internal/handlers/system.rs::handle_vps_reboot`,
`internal/conflict.rs::remove`), `apt-get` / `dnf` for the incompatible
software check (`internal/conflict.rs::command_exists`), and
`useradd` / `usermod` for tenant provisioning
(`internal/podman/mod.rs::ensure_tenant_user`, `internal/podman/mod.rs::add_subid_range`).

What authenticates: there is no authentication in the OS sense; the
agent is already root. Authentication is the signed-command path
described in 3.1, which is what authorises any of these shell-outs.

What happens on failure: per-handler `BadRequest` /
`Forbidden` / `Internal` mapping (`internal/error.rs::AgentError`), with the
specific rule that `Internal` errors are redacted to the literal
string `"internal error"` so a path or secret from the anyhow chain
never reaches the wire (`internal/handlers/system.rs::sanitize_error`,
`internal/error.rs::AgentError`).

### 3.4 Agent to tenant workloads (rootless Podman, subuid ranges, compose input)

What crosses: signed `container.deploy` / `container.list` / `start` /
`stop` / `remove` / `restart` / `update` commands carrying a tenant_id,
project_id, name, and (for deploy) a compose YAML body. The
dispatcher runs them as the corresponding tenant user via `runuser -u`,
no shell (`internal/podman/mod.rs::podman_as_tenant`).

What authenticates: the same signed-command path as 3.1. Per-handler
permission floors are at Write (`internal/handlers/containers.rs::handle_tenant_ensure`, `internal/handlers/containers.rs::handle_container_deploy`, `internal/handlers/containers.rs::handle_container_start`, `internal/handlers/containers.rs::handle_container_stop`, `internal/handlers/containers.rs::handle_container_restart`, `internal/handlers/containers.rs::handle_container_update`) or Destructive
(`internal/handlers/containers.rs::handle_container_down`, `internal/handlers/containers.rs::handle_container_remove`). The exception is
`container.list`, which has no permission floor by design (a Read-only
role may list containers for the tenants it can already see)
(`internal/handlers/containers.rs::handle_container_list`).

What happens on failure: `handle_container_deploy`
(`internal/handlers/containers.rs`) passes the compose YAML to
`validate_compose` (`internal/handlers/validate/compose/mod.rs`)
before the file lands on disk, and a refusal ends the command with a
generic `container.deploy compose rejected` while the reason is logged
on the agent; bind sources are confined to the tenant project dir, the
nginx webroot, or `/tmp` by `check_bind_source`
(`internal/handlers/validate/compose/paths.rs`); identifiers are
validated to alphanumeric, hyphen, and underscore only, length
≤128 (`internal/handlers/containers.rs::validate_id`).

### 3.5 Agent to the public internet (hosted-site nginx, certbot/ACME, GitHub release downloads)

What crosses: a signed `nginx.deploy` / `nginx.update_config` /
`nginx.install_cert` / `certbot.obtain` payload. The agent then
either renders nginx config from the payload (`internal/nginx.rs::redeploy_nginx`),
runs `podman exec helmly-nginx nginx -t -c <tmp>` to validate
syntax (`internal/handlers/nginx_cmd.rs::handle_nginx_update_config`), and reloads nginx
inside its container (`internal/handlers/nginx_cmd.rs::reload_nginx`); or
runs `certbot certonly --webroot` against the configured webroot
(`internal/handlers/nginx_cmd.rs::handle_certbot_obtain`). The self-update path
also reaches `github.com` and `objects.githubusercontent.com`
(`internal/update/mod.rs::validate_github_url`).

What authenticates: the same signed-command path as 3.1. The nginx
config is additionally passed through an allow-list walker
(`validate_nginx` in `internal/handlers/validate.rs`) and a hard-deny
list (`DENY_NGINX_DIRECTIVES` and `DENY_NGINX_PROXY_PATTERNS` in the
same file); the cert path is bounded
to a directory under `/etc/glyndor/helmly/nginx/certs/<domain>/`
where `<domain>` is itself validated against a strict character set
(`internal/handlers/nginx_cmd.rs::validate_domain_for_path`).

What happens on failure: any allow-list rejection is collapsed to a
constant `"nginx.update_config config rejected"` so attackers cannot
distinguish allowed from disallowed by response shape
(`internal/handlers/nginx_cmd.rs::handle_nginx_update_config`); nginx `-t` failure keeps
the previous config live (no swap) (`internal/handlers/nginx_cmd.rs::handle_nginx_update_config`);
certbot failure returns `Internal` with no nginx reload
(`internal/handlers/nginx_cmd.rs::handle_certbot_obtain`).

## 4. Controls, per boundary

Each entry names one control, the code that implements it, and the
file:line to read. Where multiple controls live in one block, each is
listed.

### 4.1 Inbound authentication

- **Ed25519 verify-before-execute.** Every command runs through
  `verify_command` before dispatch
  (`internal/auth/mod.rs::verify_command`). The signature is checked against
  a keyring, not a single key, so two-phase rotation works
  in-band (`internal/auth/mod.rs::verify_command`). The keyring is empty-checked
  first and rejects all commands if so
  (`internal/auth/mod.rs::verify_command`).
- **Timestamp freshness.** 30s window enforced by
  `MAX_TIMESTAMP_SKEW_SECS` (`internal/auth/mod.rs::MAX_TIMESTAMP_SKEW_SECS`) and the
  `(now - payload.timestamp).abs()` check
  (`internal/auth/mod.rs::verify_command`). The `agent.heartbeat_ack` type
  is the single documented bypass, so a stuck clock on the agent
  cannot deadlock the heartbeat path; the nonce check is still
  enforced for it (`internal/auth/mod.rs::verify_command`).
- **Nonce dedup.** Inserts into `used_nonces` with
  `ON CONFLICT DO NOTHING`, and fails if the insert returned no row
  (`internal/auth/mod.rs::check_and_consume_nonce`). The table is purged every five
  minutes via the periodic task
  (`internal/main.rs::main`, the nonce-cleanup task).
- **agent_id match.** The signed payload's `agent_id` must equal the
  configured `state.config.agent_id`, otherwise the command is
  rejected as misaddressed (`internal/auth/mod.rs::verify_command`).
- **Bearer on `/cmd`.** The HTTP `/cmd` route additionally requires
  `Authorization: Bearer <INTERNAL_TOKEN>`, compared in constant
  time (`internal/handlers/system.rs::execute_command`,
  `internal/auth/mod.rs::verify_bearer`).
- **Heartbeat ACK requires Ed25519, not the bearer.** The `/heartbeat`
  HTTP route invokes `verify_command` directly and rejects with 401
  on any signature failure (`internal/main.rs::heartbeat_handler`). This is so
  a stolen `INTERNAL_TOKEN` alone cannot silence lockdown.
- **Lockdown gate on `/cmd`.** The HTTP `/cmd` route short-circuits
  to `Lockdown` (503) if the agent is in lockdown
  (`internal/handlers/system.rs::execute_command`). The WebSocket
  heartbeat-ack path bypasses this gate (so the dashboard can rescue
  a locked-down agent) but every other WebSocket command does not
  (`internal/ws_client.rs::handle_message`).

### 4.2 Permission enforcement (per-handler floors)

- **Three-tier permission model.** `Read` < `Write` < `Destructive`,
  enforced by per-handler `if cmd.permission == Read` /
  `if cmd.permission < Write` / `if cmd.permission != Destructive`
  gates. The exhaustive set on this branch:
  - `update.self` requires Write (`internal/handlers/system.rs::handle_update_self`).
  - `dashboard.migrate` requires Write
    (`internal/handlers/system.rs::handle_dashboard_migrate`).
  - `cert.update` requires Write (`internal/handlers/system.rs::handle_cert_update`).
  - `db.rotate_password` requires Write
    (`internal/handlers/system.rs::handle_db_rotate_password`).
  - `vps.reboot` requires Write (`internal/handlers/system.rs::handle_vps_reboot`).
  - `nftables.apply`, `nftables.restore`, `nftables.accept` require
    Write (`internal/handlers/nftables.rs::handle_nftables_apply`, `internal/handlers/nftables.rs::handle_nftables_restore`, `internal/handlers/nftables.rs::handle_nftables_accept`).
  - `nginx.deploy`, `nginx.update_config`, `nginx.install_cert`,
    `certbot.obtain` require Write
    (`internal/handlers/nginx_cmd.rs::handle_nginx_deploy`, `internal/handlers/nginx_cmd.rs::handle_nginx_update_config`, `internal/handlers/nginx_cmd.rs::handle_nginx_install_cert`, `internal/handlers/nginx_cmd.rs::handle_certbot_obtain`).
  - `nftables.close_setup_port` requires Write
    (`internal/handlers/nginx_cmd.rs::handle_close_setup_port`).
  - `tenant.ensure`, `container.deploy`, `container.start`,
    `container.stop`, `container.restart`, `container.update` require
    Write (`internal/handlers/containers.rs::handle_tenant_ensure`, `internal/handlers/containers.rs::handle_container_deploy`, `internal/handlers/containers.rs::handle_container_start`, `internal/handlers/containers.rs::handle_container_stop`, `internal/handlers/containers.rs::handle_container_restart`, `internal/handlers/containers.rs::handle_container_update`).
  - `container.down`, `container.remove` require Destructive
    (`internal/handlers/containers.rs::handle_container_down`, `internal/handlers/containers.rs::handle_container_remove`).
  - `wg.rotate_psk`, `wg.data_plane.setup`,
    `wg.data_plane.teardown`, `wg.management.add_peer`,
    `wg.management.remove_peer`, `wg.management.list_peers` require
    Write (`internal/handlers/wireguard.rs::handle_wg_rotate_psk`, `internal/handlers/wireguard.rs::handle_wg_data_plane_setup`, `internal/handlers/wireguard.rs::handle_wg_data_plane_teardown`, `internal/handlers/wireguard.rs::handle_wg_management_add_peer`, `internal/handlers/wireguard.rs::handle_wg_management_remove_peer`, `internal/handlers/wireguard.rs::handle_wg_management_list_peers`).
  - `container.list` has no gate, by design
    (`internal/handlers/containers.rs::handle_container_list`).
- **What is not enforced at the agent.** The agent enforces the floor
  per handler but does not carry a command-to-level map independent
  of the dashboard's `permission` claim inside the signed payload.
  See Gaps, the item on the dashboard's claimed `permission` field.

### 4.3 Transport (mTLS)

- **mTLS listener, fail-closed.** `build_tls_acceptor` returns
  `Ok(None)` only when `INSECURE_PLAIN_HTTP=1` is set explicitly,
  with a loud warn-level log on every startup that uses it
  (`internal/server.rs::build_tls_acceptor`). On any other failure mode (missing,
  partial, malformed-DER), the function returns `Err` and
  `main.rs` calls `process::exit(1)` before the listener opens
  (`internal/main.rs::main`).
- **Client cert verifier.** The server config trusts only the
  supplied `TLS_CA_CERT_DER_FILE` (`internal/server.rs::build_tls_acceptor`). A
  client presenting any other CA fails the handshake.
- **INSECURE_PLAIN_HTTP as a debug switch.** Setting
  `INSECURE_PLAIN_HTTP=1` is the only way to serve plain HTTP, and
  the log line on use is explicit about it being a dev-only escape
  (`internal/server.rs::build_tls_acceptor` and `internal/main.rs::main`). See "Closed gaps" in 5: an install that cannot start the listener has
  a missing or wrong TLS blob, and that is what to fix.

### 4.4 Dashboard verify keyring

- **File-first loader.** `/etc/glyndor/helmly/dashboard-keyring`
  takes precedence over the legacy `DASHBOARD_VERIFY_KEY` env var
  (`internal/config.rs::load_dashboard_keyring`). One b64 32-byte public key per
  line; blank and `#` lines are skipped
  (`internal/config.rs::load_dashboard_keyring_at`).
- **Perm gate.** The keyring file must be mode `0o600` or stricter;
  group- or world-readable files are refused before any byte is read
  (`internal/config.rs::load_key32_opt`).
- **Length gate.** Each line must decode to exactly 32 bytes
  (`internal/config.rs::load_dashboard_keyring_at`).
- **Seed-on-load.** If the env var is set but the file is absent,
  the file is written atomically (`O_EXCL`, `tmp + rename`, mode
  `0o600`) so the next start reads the ring instead of the env
  (`internal/config.rs::load_dashboard_keyring_at`, `internal/config.rs::seed_keyring_file_at`). This keeps single-key
  legacy installs verifying under the same loader.
- **Empty keyring fail-closed.** A successful load that returns zero
  keys is rejected at the top of `verify_command`
  (`internal/auth/mod.rs::verify_command`).
- **Keyring iteration.** `try_verify_keys` is the inner loop that
  honours "first match wins, unordered", and is testable without a
  DB (`internal/auth/mod.rs::try_verify_keys`). The production caller composes
  the keyring with `verify_command` directly
  (`internal/auth/mod.rs::verify_command`).

### 4.5 Outbound authentication

- **WebSocket upgrade.** The agent appends `?token=<SYNC_TOKEN>` to
  the upgrade URL (`internal/ws_client.rs::run_ws_client`).
- **Audit sync.** HTTP `POST` carries `Authorization: Bearer
  <SYNC_TOKEN>` (`internal/sync/mod.rs::sync_batch`).
- **Divergence notification.** HTTP `POST` carries the same
  `Authorization: Bearer <SYNC_TOKEN>` header
  (`internal/nftables/divergence.rs::notify_dashboard`).

### 4.6 Audit integrity

- **Hash chain.** Each audit row carries `previous_hash` (the
  previous row's `entry_hash`) and `entry_hash` (SHA-256 of a
  deterministic concatenation of every written column)
  (`internal/audit/mod.rs::compute_entry_hash`). The input to the hash covers
  `prev_hash || id || agent_id || org_id || user_id || command_type ||
  result || error` (`internal/audit/mod.rs::compute_entry_hash`).
- **Chain verification on every append.** Before writing the next
  entry, `append` recomputes the last entry's hash and refuses to
  extend a broken chain (`internal/audit/mod.rs::append`).
- **Genesis sentinel.** The first row's `previous_hash` is the
  literal string `"genesis"` (`internal/audit/mod.rs::append`).
- **Hash mismatch detection.** A recomputed hash that does not match
  the stored one logs a `CRITICAL` trace and bails
  (`internal/audit/mod.rs::append`).
- **Sync cursor reset on chain mismatch.** A `422` from the dashboard
  (hash chain rejected) resets the local `sync_state.last_synced_at`
  to epoch so the next cycle resends from genesis
  (`internal/sync/mod.rs::sync_batch`).
- **Error redaction on the audit log.** `AgentError::Internal` is
  collapsed to the literal `"internal error"` before being written
  to the audit row, so secrets in the anyhow chain never reach the
  row (`internal/handlers/system.rs::sanitize_error`,
  `internal/error.rs::AgentError`).

### 4.7 nftables

- **Atomic full-table apply.** Every dashboard `nftables.apply`
  rebuilds the whole `table inet helmly-agent` and runs `nft -f -`
  on it (`internal/nftables/mod.rs::apply`). A partial mutation
  through `nft add rule` would be wiped by the next apply.
- **Base chain invariants.** `helmly-base` carries the immutable
  invariants (WireGuard management plane, ICMP, SSH rate-limited by
  `ssh_throttle`, established/related, loopback) and is never
  reachable from the dashboard command surface
  (`internal/nftables/mod.rs::render_ruleset`). The dashboard can only
  write to `helmly-global`, `helmly-local`, `helmly-global-output`,
  `helmly-local-output` (`internal/handlers/nftables.rs::handle_nftables_apply`).
- **Dashboard command types.** `nftables.apply` (with optional
  per-chain body) and `nftables.restore` (re-applies the last
  rendered ruleset) and `nftables.accept` (operator ACK of the live
  ruleset as the new baseline) are the three mutable commands
  (`internal/handlers/nftables.rs::handle_nftables_apply`). Each requires Write.
- **Emergency ruleset.** `apply_emergency` replaces the entire table
  with a minimal ruleset that allows only WireGuard inbound,
  established, and loopback; everything else is dropped
  (`internal/nftables/mod.rs::apply_emergency`, `internal/nftables/mod.rs::EMERGENCY_RULESET`).
- **Divergence detection.** A 60-second timer
  (`internal/nftables/divergence.rs::CHECK_INTERVAL_SECS`, `internal/nftables/divergence.rs::run_divergence_check`) recomputes a SHA-256
  of `nft -j -t list table inet helmly-agent` and compares it
  against the stored expected checksum
  (`internal/nftables/mod.rs::current_checksum`). A mismatch triggers a
  per-chain attribution and an auto-restore from the
  `nft_last_ruleset` cache (`internal/nftables/divergence.rs::check_once_with`, `internal/nftables/divergence.rs::restore_with`).
- **Per-chain checksums.** Three expected checksums are kept
  (`base`, `global`, `local`) so the divergence detector can name
  the chain that diverged (`internal/nftables/divergence.rs::check_once_with`, `internal/nftables/divergence.rs::is_chain_diverged_with`). A `helmly-base` divergence is logged as `CRITICAL`
  rather than `warn` because the base chain is supposed to be
  immutable (`internal/nftables/divergence.rs::check_once_with`).
- **Lockdown on failed restore.** If `restore_with` errors AND the
  emergency ruleset also errors, the agent enters lockdown with
  reason `NftablesFailure` (`internal/nftables/divergence.rs::check_once_with`,
  `internal/state.rs::LockdownReason`).
- **Persistence.** `apply` writes the rendered ruleset to
  `/etc/nftables-helmly-agent.conf` so nftables.service can reload
  it at boot (`internal/nftables/mod.rs::persist_ruleset`). At agent startup,
  the ruleset is re-read from `nftables_state` and re-applied
  (`internal/main.rs::main`).
- **PG watchdog → lockdown.** A 30-second timer
  (`internal/main.rs::main`) issues `SELECT 1`; an error sets
  `LockdownReason::PgUnreachable` (`internal/main.rs::main`).
- **Heartbeat watchdog → lockdown.** A 30-second timer checks the
  elapsed since `last_heartbeat`; >300s sets
  `LockdownReason::Heartbeat` (`internal/main.rs::HEARTBEAT_TIMEOUT_SECS` and `internal/main.rs::main`).
- **Lockdown state machine.** `clear_lockdown_if_heartbeat` clears
  the flag only when the reason is `Heartbeat` or `None`; the
  other reasons (`PgUnreachable`, `IncompatibleSoftware`,
  `NftablesFailure`) require a manual service restart to clear
  (`internal/state.rs::clear_lockdown_if_heartbeat`).
- **Command rate limiter.** A 100/min sliding-window counter; on
  exhaustion, the command is rejected with `BadRequest("rate limit
  exceeded")` and the rejection is counted
  (`internal/state.rs::check_cmd_rate`, `internal/handlers/system.rs::run_verified_command`).
  A separate per-minute counter records rate-limit rejections and
  fires a `warn!` at 3 (`internal/handlers/system.rs::run_verified_command`,
  `internal/state.rs::record_rate_rejection`).

### 4.8 Self-update

- **Two-slot release keyring.** The compiled-in `RELEASE_PUBKEYS`
  carries an active slot (the `HFv7vg5FCY7YyKUDbJhaQSfB9SboJGSblJtFbLmLHzM=`
  key) and an all-zero slot for two-phase rotation; both slots
  all-zero fails closed (`internal/update/mod.rs::RELEASE_PUBKEYS`, `internal/update/mod.rs::verify_signature_with`).
- **Signature verify-before-execute.** The downloaded binary is
  checked against the keyring before any write to disk
  (`internal/update/mod.rs::perform_update`). A failure is `bail!` before the
  `tmp` file is written, so a bad download never touches the binary
  path.
- **URL allow-list.** Both `download_url` and `sig_url` must start
  with `https://github.com/` or `https://objects.githubusercontent.com/`
  (`internal/update/mod.rs::validate_github_url`). The dashboard can sign a
  command with any URL it likes; the allow-list is the only thing
  that decides whether the agent ever fetches it.
- **SSRF guard.** `build_ssrf_safe_client` resolves DNS once, rejects
  RFC1918 / loopback / link-local / ULA / unspecified addresses
  (`internal/update/mod.rs::build_ssrf_safe_client`), and pins the hostname to the
  validated IP via `reqwest::ClientBuilder::resolve`, so a
  DNS-rebinding `github.com → 127.0.0.1` swap is impossible
  (`internal/update/mod.rs::build_ssrf_safe_client`).
- **Size cap.** 200 MiB cap on both the `Content-Length` hint and
  the post-read body length (`internal/update/mod.rs::download_bytes_with`).
- **Atomic swap.** `.new` is written and chmod `0o755`, the current
  binary is copied to `.prev`, and the swap is `rename(2)`
  (`internal/update/mod.rs::perform_update`). systemd's `Restart=always`
  brings the new binary up.
- **Rollback on bad health.** A 30-second post-startup health loop
  polls `http://127.0.0.1:9090/health`; on persistent failure it
  restores `.prev` over the live binary and writes `/etc/glyndor/helmly/CRITICAL`
  with the reason (`internal/update/mod.rs::spawn_startup_health_guard`).
- **dpkg refusal.** If `/etc/glyndor/helmly/.install-method` contains
  `dpkg`, the self-update path `bail!`s with an instruction to run
  `apt upgrade` instead (`internal/update/mod.rs::check_install_method_marker_at`). The
  setup script writes `script` by default
  (`setup-agent.sh::.install-method`).
- **Fallback updater.** When the dashboard has not been contacted
  for 6 hours, the agent polls `https://api.github.com/repos/Glyndor/helmly-agent/releases`,
  picks the first `v*` tag, and applies the same signed-binary path
  (`internal/update/fallback.rs::ABSENT_THRESHOLD_SECS`, `internal/update/fallback.rs::run_fallback_updater`). The fallback is
  skipped entirely if `DASHBOARD_URL` is unset, so an unenrolled
  agent never triggers an update loop
  (`internal/update/fallback.rs::run_fallback_updater`).
- **Service account.** `setup-agent.sh` installs the binary to
  `/etc/glyndor/helmly/bin/helmly-agent` and runs it as **root**: the
  unit sets `User=root` and `Group=root`
  (`setup-agent.sh::helmly-agent.service`). The `helmly-agent` system user
  exists but does not run the daemon. See the first asset in 2 and the
  item on root in 5.

### 4.9 Container isolation

- **Rootless Podman via runuser, no shell.** Each podman invocation
  uses `runuser -u <tenant> -- podman <args>`, with each argument
  passed directly to the OS, not through a shell
  (`internal/podman/mod.rs::podman_as_tenant`). A malicious `tenant_id` cannot
  carry `;` or `$(id)` because the identifier is validated to
  alphanumeric / hyphen / underscore only
  (`internal/handlers/containers.rs::validate_id`).
- **Per-tenant system user and subuid/subgid.** `ensure_tenant_user`
  creates `helmly-tenant-<id>` with a real home dir under
  `/var/lib/glyndor/helmly/orgs/<id>` and assigns a 65,536-ID
  subuid/subgid range starting from the next free slot above 100,000
  (`internal/podman/mod.rs::ensure_tenant_user`, `internal/podman/mod.rs::add_subid_range`).
- **HOME and XDG_RUNTIME_DIR are set per call.** The podman invocation
  sets `HOME=/var/lib/glyndor/helmly/orgs/<id>` and
  `XDG_RUNTIME_DIR=/run/user/<uid>` so rootless Podman finds its
  storage and socket (`internal/podman/mod.rs::podman_as_tenant`).
- **Compose validation runs before the file is written.**
  `validate_compose` (`internal/handlers/validate/compose/mod.rs`) takes
  the YAML and a `ComposePolicy`: the project directory the file is
  written to and run from (`podman::project_dir`), and the host ports the
  agent itself uses (`reserved_host_ports` in
  `internal/handlers/containers.rs`: the listener port, the WireGuard
  port, the setup port and, where set, the dashboard port). It makes
  three passes over the parsed document, one file per family under
  `internal/handlers/validate/compose/`: `structure.rs`, then
  `document.rs`, then the key rules of `keys.rs`. Every refusal names the
  key and the reason, and a value in a shape a rule cannot read is
  refused rather than skipped.
- **YAML constructs that make a runner read something else are
  refused anywhere** (`structure::check`). YAML tags, keys that are not
  strings, merge keys (`<<`) and any unescaped `$` are rejected, so the
  other rules see plain strings, lists and maps and the runner substitutes
  nothing after validation; `$$` is accepted as a literal `$`.
- **Top-level rules** (`document::check`). A top-level `name` and any
  `x-podman*` extension are rejected. `services` must be a mapping of
  mappings. A named volume whose `driver_opts` bind a host path (`o`
  containing `bind` or `rbind`, or a `device` other than `tmpfs`) is
  rejected, as is a network whose `name` or `driver` is `host`.
- **Deny-listed keys at any depth** (`DENY_KEYS` in `keys.rs`):
  `privileged`, `cap_add`, `cgroup_parent`, `devices`,
  `device_cgroup_rules`, `sysctls`, `tmpfs`, `runtime`, `volumes_from`,
  `extends`, `include`, `env_file`, `label_file`, `build`. An `x-` key is
  accepted only at the top level, and a `file` or `environment` source
  inside `secrets` or `configs` is rejected.
- **Value rules** (`values.rs`). `init` must be `true` when present.
  `network_mode`, `pid`, `ipc`, `uts` and `cgroup` may not name the host,
  another container or service (`container:`, `service:`), or a
  namespace by path (`ns:`), and `network_mode` may not carry
  `slirp4netns:` or `pasta:` options. `userns_mode` may only be `auto`.
  `cap_drop` may not contain `ALL`, in any case and with or without the
  `CAP_` prefix, because a rootless container that drops every capability
  is outside the security model. `security_opt` rejects any `seccomp`
  or `unmask` entry, `apparmor` and `systempaths` set to `unconfined`,
  and `label` set to `disable` or to a `type:`. The label
  `io.containers.autoupdate` is rejected.
- **Volume source allow-list** (`volumes.rs`, `paths.rs`). A service
  volume is checked in its short form (`source:target[:options]`) and its
  long form. A source that starts with `/`, `.` or `~` is a host path, and
  so is a `bind` source and a `volume` source written as a path. A
  host path is resolved against the project directory through every
  symbolic link that exists, and must then lie under the project
  directory, under the nginx webroot
  (`/var/lib/glyndor/helmly/nginx/webroot`), or under `/tmp`; `..`, `~`
  and an empty source are rejected. A long-form mount needs a `type`, and
  only `bind` and `volume` are accepted.
- **Host aliases and ports** (`hosts.rs`, `ports.rs`). `extra_hosts`
  accepts only literal IP addresses, and rejects `host-gateway`, loopback,
  unspecified and link-local addresses (including the address a
  slirp4netns container uses for the host, `10.0.2.2`, and IPv4-mapped
  forms). `ports` may not publish a host port, or a range that contains
  one, that the agent itself uses, whatever the protocol or host address.
- **Tenant project dir is chowned to the tenant user** so the
  tenant process can read its own compose file
  (`internal/podman/mod.rs::compose_up_no_recreate`).
- **Startup recovery.** On boot, the agent queries
  `container_deployments` where `desired = 'running'` and runs
  `podman compose up --no-recreate` for each, so reboots restore
  the desired state (`internal/main.rs::main`).
- **Migration path sync (`dashboard.migrate`).** When a node is
  migrated, the handler validates `target_url` against
  `DASHBOARD_URL`: same scheme (`http` or `https`), same host
  (case-insensitive), same port (or scheme default), and a DNS
  resolution that is not private / loopback / link-local / ULA /
  multicast / broadcast (`internal/handlers/system.rs::validate_migrate_target`).
  The check reuses `is_private_ip`-like predicates
  (`internal/handlers/system.rs::is_private_or_reserved_ip`).

### 4.10 Hosted-site nginx (distinct from the dashboard↔agent mTLS)

- **Block-directive allow-list.** Only `events`, `http`, `server`,
  `location`, `upstream`, `map` may open a brace block
  (`ALLOWED_NGINX_DIRECTIVES`, checked by `validate_nginx` in
  `internal/handlers/validate.rs`).
- **Leaf-directive allow-list.** Inside those blocks, only the 40
  reverse-proxy directives of `ALLOWED_NGINX_LEAF_DIRECTIVES` are
  allowed, and `events` accepts only `worker_connections`
  (`validate_nginx`).
- **Hard-deny directives.** `dgram_access`, `perl_modules`,
  `perl_require`, `load_module`, `secure_link_secret`, `ssl_engine`,
  `aio`, `thread_pool`, `js_import`, `js_content`,
  `client_body_temp_path`, `fastcgi_param`, `uwsgi_param`, `scgi_param`
  (`DENY_NGINX_DIRECTIVES`) are denied even if nginx accepts them.
- **proxy_pass unix-socket deny.** Any `proxy_pass` value that
  contains `unix:/var/run/docker.sock` or `unix:/var/run/podman/`
  (`DENY_NGINX_PROXY_PATTERNS`) is rejected.
- **Brace-balance check.** After the structural walk, an
  unbalanced brace count is rejected (the end of `validate_nginx`).
- **Allow-list + `nginx -t` defence-in-depth.** `nginx.update_config`
  writes the staged config to `NGINX_TMP_CONFIG_PATH`
  (`/etc/nginx/conf.d/helmly.conf.new`), runs
  `podman exec helmly-nginx nginx -t -c <tmp>`, and only swaps on success
  (`internal/handlers/nginx_cmd.rs::handle_nginx_update_config`). The temp
  file is inside `/etc/nginx/conf.d/`, so it is the `.new` suffix and not its
  location that keeps a live `include *.conf;` from picking it up before the
  test passes; the code comment above the write still says "outside
  /etc/nginx", which is not what the constant does.
- **nginx watchdog.** A 60-second timer checks `helmly-nginx` is
  running and that `http://127.0.0.1:80/_health` returns 2xx
  (`internal/nginx.rs::run_nginx_watchdog`). On a missing container with prior
  existence, it redeploys up to 3 times with exponential backoff
  (`internal/nginx.rs::redeploy_nginx`). On a present-but-unhealthy
  container, it re-runs the allow-list and `nginx -t` on the most
  recent persisted config from the DB and reloads
  (`internal/nginx.rs::restore_nginx_config`).
- **Domain validation.** A cert `domain` is alphanumeric, hyphen,
  and dot only; length ≤253; no `..`, no `/`, no NUL; cannot start
  or end with `.` (`internal/handlers/nginx_cmd.rs::validate_domain_for_path`). The
  cert and key are then written to
  `/etc/glyndor/helmly/nginx/certs/<domain>/{fullchain.pem,privkey.pem}`
  (`internal/handlers/nginx_cmd.rs::handle_nginx_install_cert`).
- **Certbot webroot.** `certbot certonly --webroot` runs against
  `/var/lib/glyndor/helmly/nginx/webroot`
  (`internal/handlers/nginx_cmd.rs::handle_certbot_obtain`). The webroot itself
  is also an allowed volume source (`WEBROOT` in
  `internal/handlers/validate/compose/paths.rs`).

### 4.11 Secret handling

- **`Zeroizing` wrappers.** `internal_token`, `sync_token`,
  `dashboard_verify_keys`, `tls_key_der` are wrapped in
  `zeroize::Zeroizing` so the heap copy is wiped on drop
  (`internal/config.rs::Config`).
- **`_FILE` env precedence.** `INTERNAL_TOKEN_FILE`,
  `SYNC_TOKEN_FILE`, `DATABASE_URL_FILE`,
  `DASHBOARD_VERIFY_KEY_FILE` (set in `setup-agent.sh::DASHBOARD_VERIFY_KEY_FILE`)
  take precedence over the inline env, and the file content is
  trimmed before use (`internal/config.rs::load_secret`).
- **systemd `LoadCredential`.** The systemd unit declares
  `LoadCredential=internal-token:…`, `LoadCredential=sync-token:…`,
  `LoadCredential=database-url:…`
  (`setup-agent.sh::LoadCredential`). The credential files are mode
  `0o600`, root-owned (`setup-agent.sh::/etc/glyndor/helmly/credentials`).
- **WireGuard PSK persisted mode `0o600`.** After a `wg.rotate_psk`,
  the PSK is written to
  `/etc/glyndor/helmly/credentials/helmly-wg-psk` and chmod `0o600`
  (`internal/handlers/wireguard.rs::PSK_PATH`).
- **wg data-plane interface config mode `0o600`.** The
  `wg-helmly-dp-<id>.conf` file is opened with `mode(0o600)`
  (`internal/handlers/wireguard.rs::handle_wg_data_plane_setup`).
- **PostgreSQL credential mode `0o600`.** `db.rotate_password`
  rewrites `/etc/glyndor/helmly/credentials/database-url` and
  `chmod 600`s it (`internal/handlers/system.rs::update_database_url_credential`).
- **Internal-error redaction.** `AgentError::Internal` is collapsed
  to `"internal error"` for `Display`, HTTP wire body, and audit
  log entries, so a secret-bearing anyhow chain never reaches any
  of those surfaces (`internal/error.rs::AgentError`, `internal/error.rs::into_response`,
  `internal/handlers/system.rs::sanitize_error`).

### 4.12 Conflict detection

- **Incompatible-software list.** A static list of `docker`,
  `containerd`, `firewalld`, `ufw`, and legacy `iptables` is
  scanned every 5 minutes (`internal/conflict.rs::INCOMPATIBLE`, `internal/conflict.rs::run_conflict_check`).
  The `iptables` check distinguishes the harmless nftables
  compatibility shim from the legacy backend by the literal
  `(legacy)` marker in `--version` output
  (`internal/conflict.rs::is_present`, `internal/conflict.rs::is_legacy_iptables`).
- **Removal.** If any package is found, it is purged via
  `apt-get purge` (Debian/Ubuntu) or `dnf remove` (RHEL)
  (`internal/conflict.rs::remove`).
- **Failure mode.** Removal failure records an audit entry with
  `Failed` and enters `LockdownReason::IncompatibleSoftware`
  (`internal/conflict.rs::check_and_remove`, `internal/conflict.rs::record_audit`).

## 5. Known gaps

Each item lists what is missing, what an attacker gains from it, and
the issue reference where one exists. A gap that has been closed is
moved to "Closed gaps" at the end of 5, with how it was closed, so that
an older copy of this text is not taken for the current state.

- **`peek_inner_command_type` steers control flow off an
  unverified payload.** `internal/ws_client.rs::peek_inner_command_type` decodes the
  base64url payload and reads `command.type` to decide whether the
  incoming WebSocket command is `agent.heartbeat_ack` and may
  bypass the lockdown gate. Full Ed25519 verification does happen
  later in `run_verified_command` (`internal/ws_client.rs::handle_message`), but
  the decision to short-circuit is already made on attacker-shaped
  bytes. An attacker that can reach the WS port cannot forge a
  valid signature, so they cannot ultimately execute; they can
  however influence which code path an *invalid* message reaches,
  including starving real heartbeats by replaying malformed
  envelopes that exercise this branch.
- **No enrollment; the install script collects nine values
  interactively.** The prompts in `setup-agent.sh::DASHBOARD_ENDPOINT`
  ask for `DASHBOARD_ENDPOINT`, `DASHBOARD_PUBKEY`, `PSK`,
  `AGENT_WG_IP`, `SYNC_TOKEN`, `DASHBOARD_SIGN_PUBKEY` and the three
  mTLS blobs (`tls_cert_der`, `tls_key_der`, `tls_ca_cert_der`) from a
  human operator, with no out-of-band proof that they own the
  dashboard they claim to. There is no single-use enrollment token
  and no way for the agent to verify the `DASHBOARD_ENDPOINT` against
  anything but a `wg show` peer post-install. What the design calls
  the "setup port" is an nftables rule that `setup-agent.sh` opens on
  the dashboard VPS (`tcp dport 19443 ct state new accept`). The
  handler that closes it works (see "Closed gaps"), but the agent
  keeps no timer of its own: how long the port stays open is
  decided by when the dashboard sends `nftables.close_setup_port`.
- **No revocation, no agent certificate rotation cadence, no
  quarantine.** `cert.update` rotates the agent's X.509 identity
  on a signed Write-level command
  (`internal/handlers/system.rs::handle_cert_update`). There is no expiration
  enforcement, no revocation list on the agent, no quarantine
  path, and no rate limit on `cert.update`. A compromised
  dashboard signing key can therefore re-issue a cert under the
  agent's identity at any pace. The CA public key
  (`internal/cert.rs::load_ca_public_key`) is loaded once at startup and never
  re-read.
- **No step-up authorisation or rate limit on destructive
  commands.** Every handler that mutates destructive state
  (`update.self`, `dashboard.migrate`, `cert.update`,
  `db.rotate_password`, `vps.reboot`, `container.down`,
  `container.remove`, `wg.management.remove_peer`) checks only the
  permission floor. The only rate limiter
  (`internal/state.rs::check_cmd_rate`) is a 100/min cap on total commands;
  individual destructive commands have no separate throttle, no
  confirmation token, and no MFA challenge. The dashboard's
  authority is whatever the signed payload claims it is.
- **Agent trusts the dashboard's claimed `permission` field inside
  the signed payload without an independent command-to-level
  map.** The signer can put any of `read`, `write`, `destructive`
  in the payload, and the agent enforces only the handler-level
  floor (see 4.2). This means a compromised dashboard (or a buggy
  one) can sign a reboot as `read` and the agent rejects it at
  the handler, but it can also sign any other command as
  `destructive` without the agent independently noticing. The
  command-to-required-level map that the design says every agent
  replicates does not exist in this tree.
- **No schema validation on the inner `command` object.** The
  dispatcher's catch-all arm is `BadRequest("unknown command
  type")` (`internal/handlers/system.rs::command_dispatch`), so the
  dispatch table is in effect an agent-side allow-list and an unknown
  command is rejected. What is missing is a schema: any new command
  type added by a future dashboard release ships without an
  agent-side expectation until the next agent release, and the inner
  `command` JSON is validated by each handler and by nothing before
  it beyond `serde_json::Value`.
- **The agent runs as root.** The unit that `setup-agent.sh` writes
  sets `User=root` and `Group=root` (`setup-agent.sh::helmly-agent.service`).
  The `helmly-agent` system user exists, with a subuid range and
  linger, but the daemon does not run as it. The unit's own comment
  gives the reason: package management, nftables, system user
  creation and binary self-update all need root. The consequence is
  the first asset in 2: compromise of the agent is compromise of the
  host, and the isolation between tenants comes from rootless Podman
  under one user per tenant (4.9), not from the account the agent runs
  as. Narrowing that account is a design change and is not made here.

### 5.x The repository itself is a trust boundary this document did not model

Every gap above is about the running agent. This one is about how the agent
gets built, and it was missing from a document whose whole subject is what an
attacker can reach.

A required status check matches **by name**. So a contributor with write
access can, in one pull request, replace a thin caller with a stub job whose
display name matches the required check and whose body is `exit 0`, and the
real gate never runs. The reusable cannot close this: the caller lives in the
repository the pull request edits, and GitHub runs the pull request's version
of it.

It reaches further here than in a repository of metadata. `release.yml` signs
the release with the org's Ed25519 key, `GLYNDOR_RELEASE_ED25519_KEY`, in its
`release` job, and that job declares `environment: release`, whose deployment
policy accepts runs of `main` and of `v*` tags only. The key is an organisation
secret visible to this repository, and a job that names an environment still
receives the organisation's secrets, so what keeps a branch of this repository
from reading it is that policy, which lives in the repository settings and not
in the workflow file. This product is a root daemon that provisions mTLS
material and executes commands sent to it. A neutralised gate on this
repository is a signed artifact nobody checked.

The org accepts this while it is effectively single-maintainer, the owner plus
Dependabot, and `standards/ci` says so explicitly. It is not zero risk: the
2026-07 incident, where an unrecognised org member briefly held write on every
repository, is the scenario where it bites.

**The mitigation is ruleset-side and applies the moment a human collaborator
is added:** require review from Code Owners on `.github/workflows/**`, so a
pull request that neutralises a caller cannot merge without the owner seeing
the diff. `.github/CODEOWNERS` is on the default branch, `main` (it is the same
file on `develop`), so GitHub reads it. What is not in place is the rule that
uses it: when this was checked, `protect-main` had `require_code_owner_review:
false` and `required_approving_review_count: 0`, so the rule would still have
to be turned on. Until a collaborator exists, the control is that the owner
reviews and merges every pull request.

### 5.y The installer that pins the release key

4.8 documents verify-before-execute for the agent binary, and that control is
real. This is the hop underneath it.

`setup-agent.sh` is the root of trust for an install. `_verify_release_sig`
(`setup-agent.sh::_verify_release_sig`) checks the downloaded binary's Ed25519
signature against a key pinned in the script itself, in `PUB_KEYS_B64`
(`setup-agent.sh::PUB_KEYS_B64`). Everything downstream, the binary signature,
`SHA256SUMS` and the release pin check, rests on that constant being the real
key, and so on `setup-agent.sh` being the file the release signed.

`Glyndor/helmly`'s `install.sh`, which is what an operator runs, no longer
fetches that file from a branch. It downloads `setup-agent.sh` and
`update-agent.sh` and their `.sig` files as assets of a release of this
repository (the latest one, or the one named in `AGENT_VERSION`), verifies
both detached Ed25519 signatures against a key pinned in `install.sh`
(`HELMLY_RELEASE_PUBKEY_B64`, the same key as `PUB_KEYS_B64` here), and only
then runs `chmod 700` and `exec bash`. It refuses to run a script it cannot
verify, including when python3 with `cryptography` is missing. This was read
on 2026-11-23: `install.sh` is identical on `develop` and `main`, and the
`v2.0.1` release carries `setup-agent.sh`, `update-agent.sh` and their
signatures. The release job signs exactly the files it expects:
`.github/scripts/release/sign-artifacts.sh` refuses any other name, a link or a
folder before it reads the key, so an asset cannot ship unsigned or unlisted
with the gates still green.

**What is still open.** `install.sh` is distributed by cloning
`Glyndor/helmly`, and it carries the key that decides which scripts verify.
Write access to this repository alone no longer lets an attacker replace the
installer, because the release signing key is a separate secret. Tampering
with `helmly`'s `install.sh` still does, and so does a tampered clone: nothing
signs or pins that file. Closing that hop is what a `.deb` route would do, and
it is not what shipped. The agent cannot close it alone, since `install.sh`
lives in `Glyndor/helmly`. Tracked in #181. Piping `install.sh` into `bash`
does not work, by design: it needs its own checkout.

### Closed gaps

What was once listed above and no longer is, with how it was closed, so that an
operator holding an older copy of this text does not follow it.

- **mTLS material is provisioned by the installer (#147).** The older text said
  no installer provides it and that an operator could only start the listener
  with `INSECURE_PLAIN_HTTP=1`. `setup-agent.sh` now asks for the three blobs
  the dashboard returns at registration (`tls_cert_der`, `tls_key_der`,
  `tls_ca_cert_der`). `_write_tls_credentials` (`setup-agent.sh::_write_tls_credentials`)
  decodes all three into a staging directory first and moves them into
  `/etc/glyndor/helmly/credentials` only when every one decoded, so a bad
  value leaves nothing half written; it refuses to overwrite an existing file
  and writes each at mode `0600`. The agent env names `TLS_CERT_DER_FILE`,
  `TLS_KEY_DER_FILE` and `TLS_CA_CERT_DER_FILE` under
  `/run/credentials/helmly-agent.service/`, served by `LoadCredential`.
  `update-agent.sh` does not write or replace them, so an update keeps what
  the install put there. An install whose listener does not start for TLS
  reasons has a missing or wrong blob, and the fix is the blob, not
  `INSECURE_PLAIN_HTTP=1`, which removes the only authenticator the listener
  has.
- **The setup port is closed (#149).** The older text said the handler appended
  `tcp dport 19443 drop` after the rule that accepts the port, so the port
  stayed open while the response said it was closed.
  `close_setup_port_with` (`internal/handlers/nginx_cmd.rs::close_setup_port_with`)
  lists the chain, finds every rule that accepts the port, deletes each by
  handle and re-reads the chain before it reports success; if a rule is still
  there it returns an internal error instead of success.
- **`rcgen` is used.** It was listed as a dependency with no callers.
  `internal/tls_keypair.rs::generate` builds the self-signed certificate and
  key pair of the `gen-tls` subcommand with it, so it is a runtime dependency
  of a command the README documents.
- **The installer chain is verified on `main`.** The older text described an
  unauthenticated fetch from a branch with the verifying half only on
  `develop`. See 5.y for the state now and for what remains.

## 6. Out of scope

This document deliberately does not model:

- **The dashboard itself.** Authentication, MFA, dashboard-side
  permission scoping, the dashboard's own command-signing key,
  and the dashboard's mTLS client live in the `helmly` repository
  and are covered there. The agent verifies what the dashboard
  signs and the dashboard decides who may sign what; this
  document describes only the agent's view of that boundary.
- **The package supply chain.** Build-time dependencies
  (`Cargo.toml`), the GitHub Actions workflow that signs releases
  (`.github/workflows/release.yml` on this branch), and the
  apt-repo build are documented in `docs/` of their respective
  repositories and audited by the org release and supply-chain
  processes. The agent's runtime check is the verify-before-execute
  step described in 4.8.
- **Tenant application security.** The agent deploys whatever the
  dashboard pushes, after the walker described in 4.9. A buggy
  tenant app, an app that talks to the wrong DB, or an app with
  its own auth bug is the tenant's problem. The agent does not
  own tenant code.
- **The host kernel.** nftables, Podman, WireGuard, and systemd
  each have their own CVEs and bug streams. The agent trusts the
  kernel and userspace it sits on.
- **The WireGuard tunnel itself.** The agent reads
  `wg-helmly-agent.conf` from the installer and rotates the PSK
  via `wg.rotate_psk`; it does not manage WireGuard interface
  bring-up, peer authentication, or kernel module loading. Those
  are handled by `wg-quick` and the kernel.
- **Physical and out-of-band access.** If an attacker has root on
  the host's console, this document does not model the recovery.

## 7. Maintenance

This document is updated in the same pull request that changes any
of the following:

- Authentication: `internal/auth/mod.rs`, `internal/cert.rs`,
  `internal/config.rs`.
- Transport: `internal/server.rs` (TLS construction and the
  fail-closed branch), `internal/main.rs` (the exit on `Err`),
  `internal/ws_client.rs`.
- Update: `internal/update/mod.rs`, `internal/update/fallback.rs`,
  `update-agent.sh`.
- Isolation: `internal/nftables/mod.rs`,
  `internal/nftables/divergence.rs`, `internal/podman/mod.rs`,
  `internal/handlers/validate.rs`, `internal/handlers/validate/compose/`,
  `internal/handlers/containers.rs`.

Not after, not in a follow-up, not "later when there's time". A
review agent that diffs the code against this document and finds a
gap on a feature merged yesterday is the failure mode this rule
exists to prevent.

A refactor counts, even one that changes no behaviour. Every claim here
cites a file and the name of the function, constant or type that implements
it, as in `internal/auth/mod.rs::verify_command`, and none a line number: a
move inside a file, or a change above it, leaves such a citation true, where a
line number goes stale without anyone noticing and a citation that now points
at the wrong code still reads as evidence. #152 moved `build_tls_acceptor` and
`serve_tls` out of `internal/main.rs` and shifted everything after them, which
left thirteen line citations pointing at unrelated code and some past the end
of the file. A rename, or a move to another file, still breaks a citation, and
`tests/docs/citations.test.sh` fails when a cited file or name no longer exists.
It cannot tell that a name now does something else, so changing what a
function does means reading the sentences that cite it in the same pull
request.
