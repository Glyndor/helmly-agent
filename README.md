# helmly-agent

`helmly-agent` — hardened server-side daemon for the [Helmly panel](https://github.com/Glyndor/helmly).

It runs on each managed VPS and executes commands sent by the dashboard:
containers (rootless Podman), firewall (nftables), tunnels (WireGuard) and
system maintenance.

## Security model

- **Transport.** WireGuard plus mTLS. TLS is the default and the agent refuses
  to start when the certificates are absent or malformed. Plain HTTP requires
  setting `INSECURE_PLAIN_HTTP=1`, which exists for local development and turns
  off the listener's only authenticator.
- **Command integrity.** Every command is Ed25519-signed with a nonce and a
  30-second timestamp window, so replays are rejected even on a compromised
  transport.
- **Audit log.** Hash-chained, append-only, synced to the dashboard in real
  time.
- **Auto-update.** Binaries are Ed25519-signature-verified before any swap.

The full threat model, with the trust boundaries, the control implementing each
one, and the gaps that are open, is in
[`docs/security-architecture.md`](docs/security-architecture.md).

## Build

```bash
cargo build --release
cargo test
```

The toolchain is the one `rust-toolchain.toml` names; `rustup` installs it on
first use. The agent does not link `podup` or any other Glyndor crate: it
creates one rootless Podman user per tenant and runs `podman` as that user.

Podman is therefore a requirement of the host the agent runs on. `setup-agent.sh`
installs the distribution's `podman` package when it is missing. To install Podman
yourself on Debian and Ubuntu:

```bash
curl -fsSL https://apt.glyndor.net/install/podman | sudo sh
```

## Commands

`helmly-agent` with no subcommand runs the daemon. The subcommands are helpers
for the installer and for the operator:

| command | what it does |
|---|---|
| `logs [-f\|--follow] [--errors] [--since <time>]` | Show or stream the agent's journald logs. |
| `gen-rand <bytes> [--encoding hex\|base64]` | Print cryptographically secure random bytes. |
| `gen-uuid-v7` | Print a time-ordered UUIDv7. |
| `gen-tls --san <address>... [--out-dir <dir>]` | Create this agent's mTLS key pair (`agent.crt.der`, `agent.key.der`, mode 0600) and print the certificate's SHA-256 fingerprint. It refuses to overwrite existing files, and the private key never leaves the host. `--san` is repeatable and `--out-dir` defaults to `/etc/glyndor/helmly/tls`. |

## Configuration

The daemon reads its configuration from the environment. A secret can be given
as `NAME` or as `NAME_FILE`, the path of a file holding it (`NAME_FILE` wins
when both are set); under systemd the installer uses `LoadCredential` files.

| key | required | meaning |
|---|---|---|
| `AGENT_ID` | yes | This agent's UUID v7. |
| `DATABASE_URL` / `DATABASE_URL_FILE` | yes | PostgreSQL connection string of the agent's own database. |
| `INTERNAL_TOKEN` / `INTERNAL_TOKEN_FILE` | yes | Bearer token for the metrics WebSocket and the system endpoint. |
| `DASHBOARD_VERIFY_KEY` / `_FILE` | one of these two | The dashboard's Ed25519 verify key, base64, 32 bytes. Seeds `/etc/glyndor/helmly/dashboard-keyring` on first start. |
| `/etc/glyndor/helmly/dashboard-keyring` | one of these two | One base64 verify key per line, mode 0600. The keyring read first; it allows two-phase key rotation. |
| `TLS_CERT_DER_FILE`, `TLS_KEY_DER_FILE`, `TLS_CA_CERT_DER_FILE` | yes, all three | Paths of the server certificate, its PKCS#8 key and the dashboard's CA, in DER. The agent exits when any is missing or malformed. |
| `LISTEN_ADDR` | no | Listen address, default `0.0.0.0:9090`. |
| `DASHBOARD_URL` | no | Dashboard base URL. The outbound WebSocket to the dashboard needs this and `SYNC_TOKEN`; without either it is not started. The firewall rules also take the dashboard's WireGuard address from it. |
| `SYNC_TOKEN` / `SYNC_TOKEN_FILE` | no | Token the outbound WebSocket presents to the dashboard. |
| `DASHBOARD_PORT` | no | Dashboard panel port to open in nftables; set on the dashboard's own server only. |
| `CA_PUBLIC_KEY` / `CA_PUBLIC_KEY_FILE` | no | Base64url Ed25519 public key that verifies agent certificates issued by the dashboard. |
| `AGENT_VERSION` | no | Overrides the version the agent reports. |
| `INSECURE_PLAIN_HTTP` | no | `1` serves plain HTTP. For local development only. |
| `RUST_LOG` | no | Log filter. |

## Install

The agent is installed and updated by the Helmly installer — see
[Glyndor/helmly](https://github.com/Glyndor/helmly). `setup-agent.sh` and
`update-agent.sh` in this repository are invoked by that flow.

## Contributing & security

See [CONTRIBUTING.md](CONTRIBUTING.md) in this repository. It replaces the org-wide
guide, which describes a branch flow and a sign-off convention that do not hold here.
Report vulnerabilities privately via the Security tab — never in a public issue.

## License

[MIT](LICENSE)
