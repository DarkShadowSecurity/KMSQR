# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
AEAD nonce-budget enforcement.

AES-256-GCM with random 96-bit nonces has a birthday-bound collision risk: after
~2^32 messages under a single key the probability of a nonce repeat (which is
catastrophic for GCM confidentiality + integrity) becomes non-negligible. The
KMS therefore counts encryptions per key-version and:

  * at a SOFT threshold (~2^30): logs a warning so operators can rotate ahead of
    the limit (auto-rotation can be wired on top of this signal);
  * at a HARD threshold (~2^32): refuses further encryption under that version,
    failing CLOSED. Callers must rotate the key (creating a fresh version with a
    zero counter) to continue.

The increment+check is performed as a single atomic UPDATE ... RETURNING so the
count cannot be skipped or double-spent under concurrency. (Phase 5 moves the
hot counter to Redis for multi-replica deployments; Postgres/SQLite remain the
source of truth.)
"""
from __future__ import annotations

import logging

log = logging.getLogger("pqkms.policy")

SOFT_LIMIT = 2 ** 30   # ~1.07e9 — warn / rotate ahead
HARD_LIMIT = 2 ** 32   # birthday bound for random 96-bit nonces — refuse


class NonceBudgetExceeded(Exception):
    """Raised when a key-version has consumed its safe AES-GCM nonce budget."""


class NonceBudgetPolicy:
    def __init__(self, soft_limit: int = SOFT_LIMIT, hard_limit: int = HARD_LIMIT):
        self.soft_limit = soft_limit
        self.hard_limit = hard_limit

    def reserve(self, db, key_id: str, version: int) -> int:
        """
        Atomically reserve one encryption slot for (key_id, version).

        Returns the new usage count. Raises NonceBudgetExceeded if the hard limit
        is reached, KeyError if the version does not exist. Call BEFORE performing
        the encryption so the budget is never overshot.
        """
        c = db.conn()
        cur = c.execute(
            "UPDATE key_versions SET usage_count = usage_count + 1 "
            "WHERE key_id=? AND version=? AND usage_count < ? "
            "RETURNING usage_count",
            (key_id, version, self.hard_limit),
        )
        row = cur.fetchone()
        if row is None:
            # Either the version is missing, or the hard cap was hit.
            exists = c.execute(
                "SELECT 1 FROM key_versions WHERE key_id=? AND version=?",
                (key_id, version),
            ).fetchone()
            if exists is None:
                raise KeyError(f"{key_id}@v{version}")
            raise NonceBudgetExceeded(
                f"key {key_id} version {version} has reached its AES-GCM nonce "
                f"budget ({self.hard_limit}); rotate the key before encrypting more"
            )
        new_count = row["usage_count"]
        if new_count == self.soft_limit:
            log.warning(
                "key %s version %s crossed the soft nonce budget (%d of %d); "
                "rotate soon to stay clear of the AES-GCM birthday bound",
                key_id, version, new_count, self.hard_limit,
            )
        return new_count
