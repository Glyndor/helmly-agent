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

Depends on [`podup`](https://github.com/Glyndor/podup) as a git
dependency.

## Install

The agent is installed and updated by the Helmly installer — see
[Glyndor/helmly](https://github.com/Glyndor/helmly). `setup-agent.sh` and
`update-agent.sh` in this repository are invoked by that flow.

## Contributing & security

See the org-wide [contributing guide](https://github.com/Glyndor/.github/blob/main/CONTRIBUTING.md).
Report vulnerabilities privately via the Security tab — never in a public issue.

## License

[MIT](LICENSE)
