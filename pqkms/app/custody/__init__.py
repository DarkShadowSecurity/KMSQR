# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""Pluggable Root-KEK custody backends (passphrase today; cloud-KMS / PKCS#11 later)."""
from .base import CustodyEnvelope, RootKeyCustodian
from .passphrase import PassphraseCustodian
from .factory import make_custodian

__all__ = ["CustodyEnvelope", "RootKeyCustodian", "PassphraseCustodian", "make_custodian"]
