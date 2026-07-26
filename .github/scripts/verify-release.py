#!/usr/bin/env python3
"""Verify a release artifact's signature against the pinned public key.

Usage:
  verify-release.py <artifact-file> <pubkey-b64> [<sig-file>]

Exits non-zero if the signature does not verify against <pubkey-b64> — the
exact public key the installer and the agent's self-update pin. Run in CI
right after signing, so a release whose signature a freshly-pinned installer
would reject can never be published (the failure mode that shipped a broken
v1.4.0).
"""
import base64
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def main() -> None:
	if len(sys.argv) < 3:
		print(__doc__, file=sys.stderr)
		sys.exit(1)

	artifact = sys.argv[1]
	pubkey_b64 = sys.argv[2]
	sig_file = sys.argv[3] if len(sys.argv) > 3 else artifact + ".sig"

	pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pubkey_b64))
	with open(artifact, "rb") as f:
		data = f.read()
	with open(sig_file, "rb") as f:
		sig = f.read()

	try:
		pub.verify(sig, data)
	except InvalidSignature:
		print(
			f"error: {sig_file} does NOT verify against the pinned key "
			f"{pubkey_b64} -- the published binary would be rejected by a "
			"fresh install. Refusing to release.",
			file=sys.stderr,
		)
		sys.exit(1)

	print(f"verified {artifact} against pinned key {pubkey_b64}")


if __name__ == "__main__":
	main()
