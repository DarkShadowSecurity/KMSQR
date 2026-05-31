# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Shamir secret sharing over GF(2^8) for split custody of the operator passphrase.

The passphrase is split into N shares such that any K reconstruct it (and K-1
reveal nothing). At boot, K shares are reassembled into the passphrase, after
which custody is exactly the passphrase backend — so a KMS bootstrapped with a
plain passphrase can later be unlocked from shares of that same passphrase and
vice versa (ShamirCustodian reports backend_id "passphrase").

This is self-contained (standard SSS over the AES field, polynomial 0x11b); it
needs no external dependency. Note: at boot every replica still needs K shares
present, so this is "K-of-N at boot", not interactive remote unseal.
"""
from __future__ import annotations

import base64
import os

from .base import CustodyEnvelope, RootKeyCustodian
from .passphrase import PassphraseCustodian

# --- GF(2^8) arithmetic (AES field, reducing polynomial 0x11b) ----------------
_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x ^= (_x << 1)
    if _x & 0x100:
        _x ^= 0x11B
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _gf_div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("GF division by zero")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


def _eval_poly(coeffs: list[int], x: int) -> int:
    # Horner's method in GF(2^8).
    y = 0
    for c in reversed(coeffs):
        y = _gf_mul(y, x) ^ c
    return y


def split_secret(secret: bytes, n: int, k: int) -> list[bytes]:
    """Split `secret` into n shares, any k of which reconstruct it.
    Each share is: 1-byte x-coordinate || one GF byte per secret byte."""
    if not (2 <= k <= n <= 255):
        raise ValueError("require 2 <= k <= n <= 255")
    if not secret:
        raise ValueError("secret must be non-empty")
    shares = [bytearray([x]) for x in range(1, n + 1)]
    for byte in secret:
        coeffs = [byte] + list(os.urandom(k - 1))  # constant term = secret byte
        for s in shares:
            s.append(_eval_poly(coeffs, s[0]))
    return [bytes(s) for s in shares]


def combine_shares(shares: list[bytes]) -> bytes:
    """Reconstruct the secret from >= k shares via Lagrange interpolation at x=0."""
    if len(shares) < 2:
        raise ValueError("need at least 2 shares")
    xs = [s[0] for s in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("shares have duplicate x-coordinates")
    length = len(shares[0]) - 1
    if any(len(s) - 1 != length for s in shares):
        raise ValueError("shares have inconsistent lengths")

    out = bytearray()
    for pos in range(length):
        ys = [s[1 + pos] for s in shares]
        secret_byte = 0
        for i in range(len(shares)):
            num = den = 1
            for j in range(len(shares)):
                if i == j:
                    continue
                num = _gf_mul(num, xs[j])          # (0 - x_j) == x_j in GF(2^8)
                den = _gf_mul(den, xs[i] ^ xs[j])  # (x_i - x_j) == x_i ^ x_j
            secret_byte ^= _gf_mul(ys[i], _gf_div(num, den))
        out.append(secret_byte)
    return bytes(out)


def encode_share(share: bytes) -> str:
    return base64.b64encode(share).decode()


def decode_share(s: str) -> bytes:
    return base64.b64decode(s.strip())


class ShamirCustodian(RootKeyCustodian):
    # Reassembles the passphrase from shares, then IS passphrase custody — so the
    # envelope format is identical and interchangeable with PassphraseCustodian.
    backend_id = "passphrase"

    def __init__(self, shares: list[bytes]):
        secret = combine_shares(shares)
        try:
            passphrase = secret.decode("utf-8")
        except UnicodeDecodeError as e:
            raise ValueError("reconstructed secret is not a valid passphrase (wrong shares?)") from e
        self._inner = PassphraseCustodian(passphrase)

    def initialize(self, root_kek: bytes) -> CustodyEnvelope:
        return self._inner.initialize(root_kek)

    def unwrap(self, envelope: CustodyEnvelope) -> bytes:
        return self._inner.unwrap(envelope)
