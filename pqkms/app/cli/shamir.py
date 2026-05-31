# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Split an operator passphrase into Shamir shares for split custody.

    PQKMS_PASSPHRASE='...' python -m app.cli.shamir split --n 5 --k 3
    # distribute the printed shares to N holders; any K reconstruct the passphrase.

At boot, set PQKMS_CUSTODY_BACKEND=shamir and provide K shares via
PQKMS_SHAMIR_SHARE_FILES (comma-separated paths) or PQKMS_SHAMIR_SHARES
(comma-separated base64). The reconstructed passphrase then unlocks a KMS that
was bootstrapped with that same passphrase (the formats are interchangeable).
"""
from __future__ import annotations

import argparse
import os
import sys

from ..custody.shamir import split_secret, combine_shares, encode_share, decode_share


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli.shamir")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("split", help="split PQKMS_PASSPHRASE into shares")
    sp.add_argument("--n", type=int, required=True, help="total shares to produce")
    sp.add_argument("--k", type=int, required=True, help="threshold needed to reconstruct")
    cp = sub.add_parser("combine", help="reconstruct from base64 shares (for testing)")
    cp.add_argument("shares", nargs="+", help="base64 shares")

    args = parser.parse_args(argv)

    if args.cmd == "split":
        passphrase = os.environ.get("PQKMS_PASSPHRASE", "")
        if not passphrase:
            print("error: set PQKMS_PASSPHRASE to the passphrase to split", file=sys.stderr)
            return 2
        shares = split_secret(passphrase.encode("utf-8"), args.n, args.k)
        print(f"# {args.k}-of-{args.n} Shamir shares — distribute to separate holders")
        for i, s in enumerate(shares, 1):
            print(f"share-{i}: {encode_share(s)}")
        return 0

    if args.cmd == "combine":
        secret = combine_shares([decode_share(s) for s in args.shares])
        sys.stdout.write(secret.decode("utf-8"))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
