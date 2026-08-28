# helmly-agent security architecture

This document is the threat-model reference for the helmly-agent code on
this branch (`docs/security-architecture.md`). It is what the seven
security review agents (command-exec, firewall, transport, self-update,
container-isolation, audit-integrity, webserver) diff against.

Every claim about a control cites the file and line that implements it,
in the form `internal/auth/mod.rs:88`. A control described here but not
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
- **The WireGuard tunnel to the dashboard.** The PSK (`internal/wireguard/...`)
  and the per-peer public key live on the agent; their disclosure lets
  an attacker re-establish the management plane on their own host and
  impersonate the agent to the dashboard.
- **The audit trail's integrity.** The dashboard reconstructs an
  ordered, tamper-evident history of what the agent did. Breaking the
  chain is what hides a compromise after the fact.
- **The agent's credentials.** Three credentials matter:
  - `INTERNAL_TOKEN` (HTTP bearer, in
    `/etc/glyndor/helmly/credentials/internal-token`, served to the
    process by systemd `LoadCredential` at
    `setup-agent.sh:1036`).
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
(`internal/auth/mod.rs:22-28`), with the payload bytes base64url-encoded
and the Ed25519 signature over those bytes. The HTTP route also
carries an `Authorization: Bearer <INTERNAL_TOKEN>` header
(`internal/handlers/system.rs:149-157`). On the WebSocket the bearer
is the `SYNC_TOKEN` carried as a query parameter on the upgrade URL
(`internal/ws_client.rs:31-42`).

What authenticates: Ed25519 signature against a keyring
(`internal/auth/mod.rs:65-150`), then nonce dedup against the
`used_nonces` table (`internal/auth/mod.rs:153-177`), then
timestamp freshness against a 30s window
(`internal/auth/mod.rs:134-139`), then `agent_id` match
(`internal/auth/mod.rs:120-122`). The HTTP listener additionally
requires the bearer to match `INTERNAL_TOKEN`. The `/heartbeat` route
requires a valid Ed25519 signature, not the bearer, so a compromised
`INTERNAL_TOKEN` cannot suppress lockdown by faking heartbeats
(`internal/main.rs` `heartbeat_handler`, from line 344).

What happens on failure: rejection short-circuits to a 401/403/400 with
a redacted code (`internal/error.rs:25-38`), the command is not
dispatched, and an audit row with `result = rejected` is appended
(`internal/handlers/system.rs:78-92`).

### 3.2 Agent to dashboard (audit sync, telemetry, command responses, divergence events)

What crosses: a WebSocket carrying heartbeats, system metrics, container
metrics, and command responses (`internal/ws_client.rs:84-141`); a
periodic HTTP `POST /agents/<id>/audit-sync` carrying up to 100 audit
entries per batch (`internal/sync/mod.rs:30-134`); a best-effort
HTTP `POST /agents/<id>/events` for nftables divergence notifications
(`internal/nftables/divergence.rs:180-212`).

What authenticates: the WebSocket upgrade carries `SYNC_TOKEN` as a
URL parameter (`internal/ws_client.rs:31-42`); both HTTP POSTs carry
`Authorization: Bearer <SYNC_TOKEN>` (`internal/sync/mod.rs:88-94`,
`internal/nftables/divergence.rs:200-205`).

What happens on failure: the WebSocket reconnects with exponential
backoff capped at 300s (`internal/ws_client.rs:14-15, 67`); audit sync
errors are logged and retried on the next 60s tick
(`internal/sync/mod.rs:50-57`); a 422 from the dashboard indicating
hash-chain mismatch resets the sync cursor to epoch and resends from
genesis (`internal/sync/mod.rs:96-113`).

### 3.3 Agent to host (nftables, systemd, WireGuard, the package manager)

What crosses: shell-outs to `nft` (`internal/nftables/mod.rs:288-308`),
`wg` / `wg-quick` (`internal/handlers/wireguard.rs:19-100, 177-196`),
`systemctl` (`internal/handlers/system.rs:423-425`,
`internal/conflict.rs:149-176`), `apt-get` / `dnf` for the incompatible
software check (`internal/conflict.rs:150-176`), and
`useradd` / `usermod` for tenant provisioning
(`internal/podman/mod.rs:24-52, 317-325`).

What authenticates: there is no authentication in the OS sense; the
agent is already root. Authentication is the signed-command path
described in 3.1, which is what authorises any of these shell-outs.

What happens on failure: per-handler `BadRequest` /
`Forbidden` / `Internal` mapping (`internal/error.rs:25-38`), with the
specific rule that `Internal` errors are redacted to the literal
string `"internal error"` so a path or secret from the anyhow chain
never reaches the wire (`internal/handlers/system.rs:430-435`,
`internal/error.rs:19-20`).

### 3.4 Agent to tenant workloads (rootless Podman, subuid ranges, compose input)

What crosses: signed `container.deploy` / `container.list` / `start` /
`stop` / `remove` / `restart` / `update` commands carrying a tenant_id,
project_id, name, and (for deploy) a compose YAML body. The
dispatcher runs them as the corresponding tenant user via `runuser -u`,
no shell (`internal/podman/mod.rs:63-76`).

What authenticates: the same signed-command path as 3.1. Per-handler
permission floors are at Write (`internal/handlers/containers.rs:17-19,
31-33, 81-83, 92-94, 149-151, 161-163`) or Destructive
(`internal/handlers/containers.rs:108-110, 132-134`). The exception is
`container.list`, which has no permission floor by design (a Read-only
role may list containers for the tenants it can already see)
(`internal/handlers/containers.rs:9-13`).

What happens on failure: the compose YAML walker rejects
host-escape vectors before the file lands on disk
(`internal/handlers/containers.rs:45-51`); the volume source is
restricted to the tenant project dir, the webroot, `/tmp`, or a
relative path (`internal/handlers/validate.rs:175-237`); identifiers
are validated to alphanumeric, hyphen, and underscore only, length
≤128 (`internal/handlers/containers.rs:184-206`).

### 3.5 Agent to the public internet (hosted-site nginx, certbot/ACME, GitHub release downloads)

What crosses: a signed `nginx.deploy` / `nginx.update_config` /
`nginx.install_cert` / `certbot.obtain` payload. The agent then
either renders nginx config from the payload (`internal/nginx.rs:99-135`),
runs `podman exec helmly-nginx nginx -t -c <tmp>` to validate
syntax (`internal/handlers/nginx_cmd.rs:105-110`), and reloads nginx
inside its container (`internal/handlers/nginx_cmd.rs:147-159`); or
runs `certbot certonly --webroot` against the configured webroot
(`internal/handlers/nginx_cmd.rs:230-244`). The self-update path
also reaches `github.com` and `objects.githubusercontent.com`
(`internal/update/mod.rs:75-77, 294-304`).

What authenticates: the same signed-command path as 3.1. The nginx
config is additionally passed through an allow-list walker
(`internal/handlers/validate.rs:331-416`) and a hard-deny list
(`internal/handlers/validate.rs:305-324`); the cert path is bounded
to a directory under `/etc/glyndor/helmly/nginx/certs/<domain>/`
where `<domain>` is itself validated against a strict character set
(`internal/handlers/nginx_cmd.rs:257-272`).

What happens on failure: any allow-list rejection is collapsed to a
constant `"nginx.update_config config rejected"` so attackers cannot
distinguish allowed from disallowed by response shape
(`internal/handlers/nginx_cmd.rs:91-93`); nginx `-t` failure keeps
the previous config live (no swap) (`internal/handlers/nginx_cmd.rs:104-110`);
certbot failure returns `Internal` with no nginx reload
(`internal/handlers/nginx_cmd.rs:247-251`).

## 4. Controls, per boundary

Each entry names one control, the code that implements it, and the
file:line to read. Where multiple controls live in one block, each is
listed.

### 4.1 Inbound authentication

- **Ed25519 verify-before-execute.** Every command runs through
  `verify_command` before dispatch
  (`internal/auth/mod.rs:65-150`). The signature is checked against
  a keyring, not a single key, so two-phase rotation works
  in-band (`internal/auth/mod.rs:92-113`). The keyring is empty-checked
  first and rejects all commands if so
  (`internal/auth/mod.rs:71-76`).
- **Timestamp freshness.** 30s window enforced by
  `MAX_TIMESTAMP_SKEW_SECS` (`internal/auth/mod.rs:10`) and the
  `(now - payload.timestamp).abs()` check
  (`internal/auth/mod.rs:134-139`). The `agent.heartbeat_ack` type
  is the single documented bypass, so a stuck clock on the agent
  cannot deadlock the heartbeat path; the nonce check is still
  enforced for it (`internal/auth/mod.rs:124-133, 142`).
- **Nonce dedup.** Inserts into `used_nonces` with
  `ON CONFLICT DO NOTHING`, and fails if the insert returned no row
  (`internal/auth/mod.rs:161-175`). The table is purged every five
  minutes via the periodic task
  (`internal/main.rs:226-235`, the nonce-cleanup task).
- **agent_id match.** The signed payload's `agent_id` must equal the
  configured `state.config.agent_id`, otherwise the command is
  rejected as misaddressed (`internal/auth/mod.rs:120-122`).
- **Bearer on `/cmd`.** The HTTP `/cmd` route additionally requires
  `Authorization: Bearer <INTERNAL_TOKEN>`, compared in constant
  time (`internal/handlers/system.rs:149-157`,
  `internal/auth/mod.rs:180-187`).
- **Heartbeat ACK requires Ed25519, not the bearer.** The `/heartbeat`
  HTTP route invokes `verify_command` directly and rejects with 401
  on any signature failure (`internal/main.rs:344-360`). This is so
  a stolen `INTERNAL_TOKEN` alone cannot silence lockdown.
- **Lockdown gate on `/cmd`.** The HTTP `/cmd` route short-circuits
  to `Lockdown` (503) if the agent is in lockdown
  (`internal/handlers/system.rs:145-147`). The WebSocket
  heartbeat-ack path bypasses this gate (so the dashboard can rescue
  a locked-down agent) but every other WebSocket command does not
  (`internal/ws_client.rs:195-202`).

### 4.2 Permission enforcement (per-handler floors)

- **Three-tier permission model.** `Read` < `Write` < `Destructive`,
  enforced by per-handler `if cmd.permission == Read` /
  `if cmd.permission < Write` / `if cmd.permission != Destructive`
  gates. The exhaustive set on this branch:
  - `update.self` requires Write (`internal/handlers/system.rs:217-221`).
  - `dashboard.migrate` requires Write
    (`internal/handlers/system.rs:239-243`).
  - `cert.update` requires Write (`internal/handlers/system.rs:299-303`).
  - `db.rotate_password` requires Write
    (`internal/handlers/system.rs:345-349`).
  - `vps.reboot` requires Write (`internal/handlers/system.rs:416-420`).
  - `nftables.apply`, `nftables.restore`, `nftables.accept` require
    Write (`internal/handlers/nftables.rs:9-13, 98-102, 125-129`).
  - `nginx.deploy`, `nginx.update_config`, `nginx.install_cert`,
    `certbot.obtain` require Write
    (`internal/handlers/nginx_cmd.rs:21-25, 82-86, 181-185,
    218-222`).
  - `nftables.close_setup_port` requires Write
    (`internal/handlers/nginx_cmd.rs:279-283`).
  - `tenant.ensure`, `container.deploy`, `container.start`,
    `container.stop`, `container.restart`, `container.update` require
    Write (`internal/handlers/containers.rs:16-19, 30-33, 81-83,
    92-94, 149-151, 161-163`).
  - `container.down`, `container.remove` require Destructive
    (`internal/handlers/containers.rs:108-110, 132-134`).
  - `wg.rotate_psk`, `wg.data_plane.setup`,
    `wg.data_plane.teardown`, `wg.management.add_peer`,
    `wg.management.remove_peer`, `wg.management.list_peers` require
    Write (`internal/handlers/wireguard.rs:12-16, 108-112, 201-205,
    235-239, 282-286, 307-311`).
  - `container.list` has no gate, by design
    (`internal/handlers/containers.rs:9-13`).
- **What is not enforced at the agent.** The agent enforces the floor
  per handler but does not carry a command-to-level map independent
  of the dashboard's `permission` claim inside the signed payload.
  See Gaps, item 4.

### 4.3 Transport (mTLS)

- **mTLS listener, fail-closed.** `build_tls_acceptor` returns
  `Ok(None)` only when `INSECURE_PLAIN_HTTP=1` is set explicitly,
  with a loud warn-level log on every startup that uses it
  (`internal/server.rs:36-43`). On any other failure mode (missing,
  partial, malformed-DER), the function returns `Err` and
  `main.rs` calls `process::exit(1)` before the listener opens
  (`internal/main.rs:310-318`).
- **Client cert verifier.** The server config trusts only the
  supplied `TLS_CA_CERT_DER_FILE` (`internal/server.rs:68-75`). A
  client presenting any other CA fails the handshake.
- **INSECURE_PLAIN_HTTP as a debug switch.** Setting
  `INSECURE_PLAIN_HTTP=1` is the only way to serve plain HTTP, and
  the log line on use is explicit about it being a dev-only escape
  (`internal/server.rs:36-43` and `internal/main.rs:336`). See Gaps, item 1.

### 4.4 Dashboard verify keyring

- **File-first loader.** `/etc/glyndor/helmly/dashboard-keyring`
  takes precedence over the legacy `DASHBOARD_VERIFY_KEY` env var
  (`internal/config.rs:141-160`). One b64 32-byte public key per
  line; blank and `#` lines are skipped
  (`internal/config.rs:194-200`).
- **Perm gate.** The keyring file must be mode `0o600` or stricter;
  group- or world-readable files are refused before any byte is read
  (`internal/config.rs:178-192`).
- **Length gate.** Each line must decode to exactly 32 bytes
  (`internal/config.rs:201-208`).
- **Seed-on-load.** If the env var is set but the file is absent,
  the file is written atomically (`O_EXCL`, `tmp + rename`, mode
  `0o600`) so the next start reads the ring instead of the env
  (`internal/config.rs:148-160, 234-262`). This keeps single-key
  legacy installs verifying under the same loader.
- **Empty keyring fail-closed.** A successful load that returns zero
  keys is rejected at the top of `verify_command`
  (`internal/auth/mod.rs:71-76`).
- **Keyring iteration.** `try_verify_keys` is the inner loop that
  honours "first match wins, unordered", and is testable without a
  DB (`internal/auth/mod.rs:199-216`). The production caller composes
  the keyring with `verify_command` directly
  (`internal/auth/mod.rs:92-113`).

### 4.5 Outbound authentication

- **WebSocket upgrade.** The agent appends `?token=<SYNC_TOKEN>` to
  the upgrade URL (`internal/ws_client.rs:31-42`).
- **Audit sync.** HTTP `POST` carries `Authorization: Bearer
  <SYNC_TOKEN>` (`internal/sync/mod.rs:88-94`).
- **Divergence notification.** HTTP `POST` carries the same
  `Authorization: Bearer <SYNC_TOKEN>` header
  (`internal/nftables/divergence.rs:200-205`).

### 4.6 Audit integrity

- **Hash chain.** Each audit row carries `previous_hash` (the
  previous row's `entry_hash`) and `entry_hash` (SHA-256 of a
  deterministic concatenation of every written column)
  (`internal/audit/mod.rs:41-61`). The input to the hash covers
  `prev_hash || id || agent_id || org_id || user_id || command_type ||
  result || error` (`internal/audit/mod.rs:39-58`).
- **Chain verification on every append.** Before writing the next
  entry, `append` recomputes the last entry's hash and refuses to
  extend a broken chain (`internal/audit/mod.rs:87-107`).
- **Genesis sentinel.** The first row's `previous_hash` is the
  literal string `"genesis"` (`internal/audit/mod.rs:110`).
- **Hash mismatch detection.** A recomputed hash that does not match
  the stored one logs a `CRITICAL` trace and bails
  (`internal/audit/mod.rs:99-106`).
- **Sync cursor reset on chain mismatch.** A `422` from the dashboard
  (hash chain rejected) resets the local `sync_state.last_synced_at`
  to epoch so the next cycle resends from genesis
  (`internal/sync/mod.rs:96-113`).
- **Error redaction on the audit log.** `AgentError::Internal` is
  collapsed to the literal `"internal error"` before being written
  to the audit row, so secrets in the anyhow chain never reach the
  row (`internal/handlers/system.rs:430-435`,
  `internal/error.rs:19-20, 32-36`).

### 4.7 nftables

- **Atomic full-table apply.** Every dashboard `nftables.apply`
  rebuilds the whole `table inet helmly-agent` and runs `nft -f -`
  on it (`internal/nftables/mod.rs:65-70`). A partial mutation
  through `nft add rule` would be wiped by the next apply.
- **Base chain invariants.** `helmly-base` carries the immutable
  invariants (WireGuard management plane, ICMP, SSH rate-limited by
  `ssh_throttle`, established/related, loopback) and is never
  reachable from the dashboard command surface
  (`internal/nftables/mod.rs:202-230`). The dashboard can only
  write to `helmly-global`, `helmly-local`, `helmly-global-output`,
  `helmly-local-output` (`internal/handlers/nftables.rs:24-34`).
- **Dashboard command types.** `nftables.apply` (with optional
  per-chain body) and `nftables.restore` (re-applies the last
  rendered ruleset) and `nftables.accept` (operator ACK of the live
  ruleset as the new baseline) are the three mutable commands
  (`internal/handlers/nftables.rs:5-136`). Each requires Write.
- **Emergency ruleset.** `apply_emergency` replaces the entire table
  with a minimal ruleset that allows only WireGuard inbound,
  established, and loopback; everything else is dropped
  (`internal/nftables/mod.rs:82-86, 95-113`).
- **Divergence detection.** A 60-second timer
  (`internal/nftables/divergence.rs:4, 6-15`) recomputes a SHA-256
  of `nft -j -t list table inet helmly-agent` and compares it
  against the stored expected checksum
  (`internal/nftables/mod.rs:116-143`). A mismatch triggers a
  per-chain attribution and an auto-restore from the
  `nft_last_ruleset` cache (`internal/nftables/divergence.rs:78-130,
  152-178`).
- **Per-chain checksums.** Three expected checksums are kept
  (`base`, `global`, `local`) so the divergence detector can name
  the chain that diverged (`internal/nftables/divergence.rs:82-84,
  132-150`). A `helmly-base` divergence is logged as `CRITICAL`
  rather than `warn` because the base chain is supposed to be
  immutable (`internal/nftables/divergence.rs:86-91`).
- **Lockdown on failed restore.** If `restore_with` errors AND the
  emergency ruleset also errors, the agent enters lockdown with
  reason `NftablesFailure` (`internal/nftables/divergence.rs:104-117`,
  `internal/state.rs:12-18`).
- **Persistence.** `apply` writes the rendered ruleset to
  `/etc/nftables-helmly-agent.conf` so nftables.service can reload
  it at boot (`internal/nftables/mod.rs:89-93`). At agent startup,
  the ruleset is re-read from `nftables_state` and re-applied
  (`internal/main.rs:129-215`).
- **PG watchdog → lockdown.** A 30-second timer
  (`internal/main.rs:248-252`) issues `SELECT 1`; an error sets
  `LockdownReason::PgUnreachable` (`internal/main.rs:253-261`).
- **Heartbeat watchdog → lockdown.** A 30-second timer checks the
  elapsed since `last_heartbeat`; >300s sets
  `LockdownReason::Heartbeat` (`internal/main.rs:37` and `internal/main.rs:293-303`).
- **Lockdown state machine.** `clear_lockdown_if_heartbeat` clears
  the flag only when the reason is `Heartbeat` or `None`; the
  other reasons (`PgUnreachable`, `IncompatibleSoftware`,
  `NftablesFailure`) require a manual service restart to clear
  (`internal/state.rs:73-82`).
- **Command rate limiter.** A 100/min sliding-window counter; on
  exhaustion, the command is rejected with `BadRequest("rate limit
  exceeded")` and the rejection is counted
  (`internal/state.rs:85-101`, `internal/handlers/system.rs:47-67`).
  A separate per-minute counter records rate-limit rejections and
  fires a `warn!` at 3 (`internal/handlers/system.rs:62-64`,
  `internal/state.rs:104-117`).

### 4.8 Self-update

- **Two-slot release keyring.** The compiled-in `RELEASE_PUBKEYS`
  carries an active slot (the `HFv7vg5FCY7YyKUDbJhaQSfB9SboJGSblJtFbLmLHzM=`
  key) and an all-zero slot for two-phase rotation; both slots
  all-zero fails closed (`internal/update/mod.rs:230-241, 254-288`).
- **Signature verify-before-execute.** The downloaded binary is
  checked against the keyring before any write to disk
  (`internal/update/mod.rs:50-52`). A failure is `bail!` before the
  `tmp` file is written, so a bad download never touches the binary
  path.
- **URL allow-list.** Both `download_url` and `sig_url` must start
  with `https://github.com/` or `https://objects.githubusercontent.com/`
  (`internal/update/mod.rs:294-304`). The dashboard can sign a
  command with any URL it likes; the allow-list is the only thing
  that decides whether the agent ever fetches it.
- **SSRF guard.** `build_ssrf_safe_client` resolves DNS once, rejects
  RFC1918 / loopback / link-local / ULA / unspecified addresses
  (`internal/update/mod.rs:311-358`), and pins the hostname to the
  validated IP via `reqwest::ClientBuilder::resolve`, so a
  DNS-rebinding `github.com → 127.0.0.1` swap is impossible
  (`internal/update/mod.rs:339-345`).
- **Size cap.** 200 MiB cap on both the `Content-Length` hint and
  the post-read body length (`internal/update/mod.rs:198-213`).
- **Atomic swap.** `.new` is written and chmod `0o755`, the current
  binary is copied to `.prev`, and the swap is `rename(2)`
  (`internal/update/mod.rs:56-77`). systemd's `Restart=always`
  brings the new binary up.
- **Rollback on bad health.** A 30-second post-startup health loop
  polls `http://127.0.0.1:9090/health`; on persistent failure it
  restores `.prev` over the live binary and writes `/etc/glyndor/helmly/CRITICAL`
  with the reason (`internal/update/mod.rs:92-180`).
- **dpkg refusal.** If `/etc/glyndor/helmly/.install-method` contains
  `dpkg`, the self-update path `bail!`s with an instruction to run
  `apt upgrade` instead (`internal/update/mod.rs:377-411`). The
  setup script writes `script` by default
  (`setup-agent.sh:938-940`).
- **Fallback updater.** When the dashboard has not been contacted
  for 6 hours, the agent polls `https://api.github.com/repos/Glyndor/helmly-agent/releases`,
  picks the first `v*` tag, and applies the same signed-binary path
  (`internal/update/fallback.rs:7, 40-81`). The fallback is
  skipped entirely if `DASHBOARD_URL` is unset, so an unenrolled
  agent never triggers an update loop
  (`internal/update/fallback.rs:25-27`).
- **Tenant-host isolation.** Setup-agent.sh installs the binary to
  `/etc/glyndor/helmly/bin/helmly-agent` and runs it as the
  `helmly-agent` system user (`setup-agent.sh:51, 1017-1086`).

### 4.9 Container isolation

- **Rootless Podman via runuser, no shell.** Each podman invocation
  uses `runuser -u <tenant> -- podman <args>`, with each argument
  passed directly to the OS, not through a shell
  (`internal/podman/mod.rs:63-76`). A malicious `tenant_id` cannot
  carry `;` or `$(id)` because the identifier is validated to
  alphanumeric / hyphen / underscore only
  (`internal/handlers/containers.rs:184-206`).
- **Per-tenant system user and subuid/subgid.** `ensure_tenant_user`
  creates `helmly-tenant-<id>` with a real home dir under
  `/var/lib/glyndor/helmly/orgs/<id>` and assigns a 65,536-ID
  subuid/subgid range starting from the next free slot above 100,000
  (`internal/podman/mod.rs:6-56, 311-351`).
- **HOME and XDG_RUNTIME_DIR are set per call.** The podman invocation
  sets `HOME=/var/lib/glyndor/helmly/orgs/<id>` and
  `XDG_RUNTIME_DIR=/run/user/<uid>` so rootless Podman finds its
  storage and socket (`internal/podman/mod.rs:71-73`).
- **Compose YAML deny-list.** The walker rejects
  `privileged`, `cap_add`, `cgroup_parent`, `devices`, `sysctls`,
  `tmpfs`, `init: false` (presence or `init: false` is rejected;
  `init: true` and absent are allowed)
  (`internal/handlers/validate.rs:24-56, 102-114`).
- **Conditional-deny values.** `network_mode: host` and
  `network_mode: container:*`, `pid: host`, `ipc: host`,
  `userns_mode` other than `auto` are rejected
  (`internal/handlers/validate.rs:39-44, 116-138`).
- **Security-opt deny.** `seccomp=unconfined`, `apparmor=unconfined`,
  `systempaths=unconfined` are rejected
  (`internal/handlers/validate.rs:46-50, 155-167`).
- **`cap_drop: ["ALL"]` is rejected.** A rootless container that
  drops all caps defeats the security model; the walker refuses it
  (`internal/handlers/validate.rs:140-153`).
- **Volume source allow-list.** A volume's `source` must be under
  the tenant project dir, under the org webroot, equal to `/tmp`,
  or relative (`internal/handlers/validate.rs:175-237`). Both the
  long form `{source: …, target: …}` and the short form
  `/host:/in:ro` are checked.
- **Tenant project dir is chowned to the tenant user** so the
  tenant process can read its own compose file
  (`internal/podman/mod.rs:150-155`).
- **Startup recovery.** On boot, the agent queries
  `container_deployments` where `desired = 'running'` and runs
  `podman compose up --no-recreate` for each, so reboots restore
  the desired state (`internal/main.rs:200-215`).
- **Migration path sync (`dashboard.migrate`).** When a node is
  migrated, the handler validates `target_url` against
  `DASHBOARD_URL`: same scheme (`http` or `https`), same host
  (case-insensitive), same port (or scheme default), and a DNS
  resolution that is not private / loopback / link-local / ULA /
  multicast / broadcast (`internal/handlers/system.rs:443-530`).
  The check reuses `is_private_ip`-like predicates
  (`internal/handlers/system.rs:539-557`).

### 4.10 Hosted-site nginx (distinct from the dashboard↔agent mTLS)

- **Block-directive allow-list.** Only `events`, `http`, `server`,
  `location`, `upstream`, `map` may open a brace block
  (`internal/handlers/validate.rs:247-253, 343-359`).
- **Leaf-directive allow-list.** Inside those blocks, only the
  documented set of ~40 reverse-proxy directives is allowed
  (`internal/handlers/validate.rs:255-301, 368-391`).
- **Hard-deny directives.** `dgram_access`, `perl_modules`,
  `load_module`, `secure_link_secret`, `ssl_engine`, `aio`,
  `thread_pool`, `js_import`, `js_content`, `client_body_temp_path`,
  `fastcgi_param`, `uwsgi_param`, `scgi_param` are denied even if
  nginx accepts them (`internal/handlers/validate.rs:305-320`).
- **proxy_pass unix-socket deny.** Any `proxy_pass` value that
  contains `unix:/var/run/docker.sock` or `unix:/var/run/podman/`
  is rejected (`internal/handlers/validate.rs:324, 392-404`).
- **Brace-balance check.** After the structural walk, an
  unbalanced brace count is rejected
  (`internal/handlers/validate.rs:410-414`).
- **Allow-list + `nginx -t` defence-in-depth.** `nginx.update_config`
  writes the staged config to a temp file outside `/etc/nginx/`,
  runs `podman exec helmly-nginx nginx -t -c <tmp>`, and only swaps
  on success (`internal/handlers/nginx_cmd.rs:78-122`). The temp
  file lives outside the include path so a live `include *.conf;`
  cannot pick it up before the test passes.
- **nginx watchdog.** A 60-second timer checks `helmly-nginx` is
  running and that `http://127.0.0.1:80/_health` returns 2xx
  (`internal/nginx.rs:13-93`). On a missing container with prior
  existence, it redeploys up to 3 times with exponential backoff
  (`internal/nginx.rs:95-135`). On a present-but-unhealthy
  container, it re-runs the allow-list and `nginx -t` on the most
  recent persisted config from the DB and reloads
  (`internal/nginx.rs:137-202`).
- **Domain validation.** A cert `domain` is alphanumeric, hyphen,
  and dot only; length ≤253; no `..`, no `/`, no NUL; cannot start
  or end with `.` (`internal/handlers/nginx_cmd.rs:257-272`). The
  cert and key are then written to
  `/etc/glyndor/helmly/nginx/certs/<domain>/{fullchain.pem,privkey.pem}`
  (`internal/handlers/nginx_cmd.rs:191-204`).
- **Certbot webroot.** `certbot certonly --webroot` runs against
  `/var/lib/glyndor/helmly/nginx/webroot`
  (`internal/handlers/nginx_cmd.rs:225-243`). The webroot itself
  is also the allow-listed volume source
  (`internal/handlers/validate.rs:230-232`).

### 4.11 Secret handling

- **`Zeroizing` wrappers.** `internal_token`, `sync_token`,
  `dashboard_verify_keys`, `tls_key_der` are wrapped in
  `zeroize::Zeroizing` so the heap copy is wiped on drop
  (`internal/config.rs:29-43`).
- **`_FILE` env precedence.** `INTERNAL_TOKEN_FILE`,
  `SYNC_TOKEN_FILE`, `DATABASE_URL_FILE`,
  `DASHBOARD_VERIFY_KEY_FILE` (set in `setup-agent.sh:957-961`)
  take precedence over the inline env, and the file content is
  trimmed before use (`internal/config.rs:106-115`).
- **systemd `LoadCredential`.** The systemd unit declares
  `LoadCredential=internal-token:…`, `LoadCredential=sync-token:…`,
  `LoadCredential=database-url:…`
  (`setup-agent.sh:1036-1038`). The credential files are mode
  `0o600`, root-owned (`setup-agent.sh:973-991`).
- **WireGuard PSK persisted mode `0o600`.** After a `wg.rotate_psk`,
  the PSK is written to
  `/etc/glyndor/helmly/credentials/helmly-wg-psk` and chmod `0o600`
  (`internal/handlers/wireguard.rs:67-77`).
- **wg data-plane interface config mode `0o600`.** The
  `wg-helmly-dp-<id>.conf` file is opened with `mode(0o600)`
  (`internal/handlers/wireguard.rs:162-174`).
- **PostgreSQL credential mode `0o600`.** `db.rotate_password`
  rewrites `/etc/glyndor/helmly/credentials/database-url` and
  `chmod 600`s it (`internal/handlers/system.rs:397-413`).
- **Internal-error redaction.** `AgentError::Internal` is collapsed
  to `"internal error"` for `Display`, HTTP wire body, and audit
  log entries, so a secret-bearing anyhow chain never reaches any
  of those surfaces (`internal/error.rs:18-20, 32-36`,
  `internal/handlers/system.rs:430-435`).

### 4.12 Conflict detection

- **Incompatible-software list.** A static list of `docker`,
  `containerd`, `firewalld`, `ufw`, and legacy `iptables` is
  scanned every 5 minutes (`internal/conflict.rs:9-35, 43-51`).
  The `iptables` check distinguishes the harmless nftables
  compatibility shim from the legacy backend by the literal
  `(legacy)` marker in `--version` output
  (`internal/conflict.rs:82-91, 129-147`).
- **Removal.** If any package is found, it is purged via
  `apt-get purge` (Debian/Ubuntu) or `dnf remove` (RHEL)
  (`internal/conflict.rs:149-177`).
- **Failure mode.** Removal failure records an audit entry with
  `Failed` and enters `LockdownReason::IncompatibleSoftware`
  (`internal/conflict.rs:66-75, 204-216`).

## 5. Known gaps

Each item lists what is missing, what an attacker gains from it, and
the issue reference where one exists.

- **No mTLS material is provisioned by any installer.** `setup-agent.sh`
  writes the agent env (`setup-agent.sh:955-966`) with no
  `TLS_CERT_DER_FILE`, `TLS_KEY_DER_FILE`, or `TLS_CA_CERT_DER_FILE`.
  `update-agent.sh` likewise does not generate or accept a client
  certificate. On any fresh install, `build_tls_acceptor` therefore
  errors out at startup (`internal/server.rs:44-55` and `internal/main.rs:310-318`) and the
  agent exits with code 1 before binding the listener. In other
  words the fail-closed branch is reachable in production, and the
  operator can only get the listener up by setting
  `INSECURE_PLAIN_HTTP=1`, which removes the only authenticator
  the listener has. Tracked in #147.
- **`peek_inner_command_type` steers control flow off an
  unverified payload.** `internal/ws_client.rs:230-237` decodes the
  base64url payload and reads `command.type` to decide whether the
  incoming WebSocket command is `agent.heartbeat_ack` and may
  bypass the lockdown gate. Full Ed25519 verification does happen
  later in `run_verified_command` (`internal/ws_client.rs:204`), but
  the decision to short-circuit is already made on attacker-shaped
  bytes. An attacker that can reach the WS port cannot forge a
  valid signature, so they cannot ultimately execute; they can
  however influence which code path an *invalid* message reaches,
  including starving real heartbeats by replaying malformed
  envelopes that exercise this branch.
- **No enrollment; the install script collects six values
  interactively.** `setup-agent.sh:239-265` prompts for
  `DASHBOARD_ENDPOINT`, `DASHBOARD_PUBKEY`, `PSK`, `AGENT_WG_IP`,
  `DASHBOARD_SIGN_PUBKEY`, and `SYNC_TOKEN` from a human operator
  with no out-of-band proof that they own the dashboard they claim
  to. There is no single-use enrollment token, no setup-port
  lifecycle, and no way for the agent to verify the
  `DASHBOARD_ENDPOINT` against anything but a `wg show` peer
  post-install. What the design calls the "setup port" is today
  just an nftables rule opened at
  `setup-agent.sh:1184-1186` (`tcp dport 19443 ct state new accept`)
  on the dashboard VPS, and `handle_close_setup_port`
  (`internal/handlers/nginx_cmd.rs:275-308`) does not close it.
  That handler appends `tcp dport 19443 drop` to the same chain,
  and `nft add rule` appends. The chain is evaluated in order and
  already accepts 19443 further up, so the appended rule is never
  reached; it sits after the chain's own trailing `drop`
  (`setup-agent.sh:1228`) as well. The handler returns
  `{"ok": true, "port": 19443}` regardless. The bounded enrollment
  window the design depends on is therefore unbounded in this tree,
  and the operator is told the opposite. Tracked in #149.
- **No revocation, no agent certificate rotation cadence, no
  quarantine.** `cert.update` rotates the agent's X.509 identity
  on a signed Write-level command
  (`internal/handlers/system.rs:295-339`). There is no expiration
  enforcement, no revocation list on the agent, no quarantine
  path, and no rate limit on `cert.update`. A compromised
  dashboard signing key can therefore re-issue a cert under the
  agent's identity at any pace. The CA public key
  (`internal/cert.rs:27-35`) is loaded once at startup and never
  re-read.
- **No step-up authorisation or rate limit on destructive
  commands.** Every handler that mutates destructive state
  (`update.self`, `dashboard.migrate`, `cert.update`,
  `db.rotate_password`, `vps.reboot`, `container.down`,
  `container.remove`, `wg.management.remove_peer`) checks only the
  permission floor. The only rate limiter
  (`internal/state.rs:85-101`) is a 100/min cap on total commands;
  individual destructive commands have no separate throttle, no
  confirmation token, and no MFA challenge. The dashboard's
  authority is whatever the signed payload claims it is.
- **`rcgen` is a direct dependency with no callers.**
  `Cargo.toml:37` declares `rcgen = { version = "0.14", features =
  ["x509-parser"] }`. A grep of `internal/` finds no use of it. It
  is dead weight in the shipped artifact and a supply-chain attack
  surface that contributes nothing to the current product.
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
- **The agent has no agent-side command type allow-list.** The
  dispatcher's catch-all arm is `BadRequest("unknown command
  type")` (`internal/handlers/system.rs:209-212`), which means an
  unknown command is rejected, but any new command type added by
  a future dashboard release ships without an agent-side
  expectation until the next agent release. There is no schema
  validation on the inner `command` JSON object beyond
  `serde_json::Value`.

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
  `internal/handlers/validate.rs`, `internal/handlers/containers.rs`.

Not after, not in a follow-up, not "later when there's time". A
review agent that diffs the code against this document and finds a
gap on a feature merged yesterday is the failure mode this rule
exists to prevent.

A refactor counts, even one that changes no behaviour. Every claim
here carries a line number, and moving code invalidates them
silently: a citation that now points at the wrong function still
reads as evidence. #152 moved `build_tls_acceptor` and `serve_tls`
out of `internal/main.rs` and shifted everything after them, which
left thirteen citations in this file pointing at unrelated code and
some past the end of the file. Relocating a function means walking
the citations to it in the same pull request, and a spot check of a
handful is what catches the ones a search for the filename misses.