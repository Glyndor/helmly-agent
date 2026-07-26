#!/usr/bin/env python3
"""Sign a file with the org Ed25519 release key.

Usage:
  sign.py <input-file> [<output-sig-file>]

The private key is read from the GLYNDOR_RELEASE_ED25519_KEY environment
variable (raw 32-byte Ed25519 seed, base64) — never passed on the command
line, so it never appears in the runner's process table. If output-sig-file
is omitted, writes to <input-file>.sig.
"""
import base64
import os
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main() -> None:
	if len(sys.argv) < 2:
		print(__doc__, file=sys.stderr)
		sys.exit(1)

	key_b64 = os.environ.get("GLYNDOR_RELEASE_ED25519_KEY")
	if not key_b64:
		print("error: GLYNDOR_RELEASE_ED25519_KEY is not set", file=sys.stderr)
		sys.exit(1)

	input_file = sys.argv[1]
	sig_file = sys.argv[2] if len(sys.argv) > 2 else input_file + ".sig"

	key_bytes = base64.b64decode(key_b64 + "==")
	private_key = Ed25519PrivateKey.from_private_bytes(key_bytes)

	with open(input_file, "rb") as f:
		data = f.read()

	sig = private_key.sign(data)

	with open(sig_file, "wb") as f:
		f.write(sig)

	print(f"signed {input_file} ({len(data):,} bytes) -> {sig_file} ({len(sig)} bytes)")


if __name__ == "__main__":
	main()
