# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Phase 9: alternative custody backends.

Shamir is exercised fully (no infra). The cloud/HSM custodians are exercised
through injected fake clients/wrappers so their envelope-first logic is covered
without AWS/GCP/an HSM; real integration is gated on that infrastructure.
"""
import itertools

import pytest

from app.crypto.aead import AEAD
from app.custody import CustodyEnvelope, PassphraseCustodian
from app.custody.shamir import split_secret, combine_shares, ShamirCustodian
from app.custody.awskms import AwsKmsCustodian
from app.custody.gcpkms import GcpKmsCustodian
from app.custody.pkcs11 import Pkcs11Custodian


# ------------------------------------------------------------------- Shamir ---

def test_shamir_split_combine_any_k_reconstructs():
    secret = b"correct horse battery staple \x00\xff\x80 unicode \xe2\x9c\x93"
    shares = split_secret(secret, n=5, k=3)
    assert len(shares) == 5
    # Every 3-subset reconstructs; no single subset is special.
    for combo in itertools.combinations(shares, 3):
        assert combine_shares(list(combo)) == secret
    # More than k also works.
    assert combine_shares(shares) == secret


def test_shamir_fewer_than_k_does_not_reconstruct():
    secret = b"top secret passphrase material"
    shares = split_secret(secret, n=5, k=3)
    # 2 shares (< k) must not yield the secret.
    assert combine_shares(shares[:2]) != secret


def test_shamir_custodian_roundtrip():
    passphrase = "a-strong-operator-passphrase"
    shares = split_secret(passphrase.encode("utf-8"), n=4, k=2)
    cust = ShamirCustodian(shares[:2])
    root = AEAD.generate_key()
    env = cust.initialize(root)
    assert cust.unwrap(CustodyEnvelope.from_bytes(env.to_bytes())) == root


def test_shamir_interoperates_with_passphrase_envelope():
    # An envelope sealed by a plain passphrase must unlock via Shamir shares of
    # that same passphrase (and vice versa) — both report backend_id "passphrase".
    passphrase = "shared-operator-passphrase-1"
    root = AEAD.generate_key()
    env = PassphraseCustodian(passphrase).initialize(root)

    shares = split_secret(passphrase.encode("utf-8"), n=3, k=2)
    assert ShamirCustodian(shares[:2]).unwrap(env) == root


# ----------------------------------------------------------------- AWS KMS ---

class _FakeKmsClient:
    """Minimal envelope-faithful stand-in for boto3 kms (XORs, not real crypto)."""
    def __init__(self):
        self.key_id = "arn:aws:kms:region:acct:key/abc"
    def encrypt(self, KeyId, Plaintext):  # noqa: N803
        return {"CiphertextBlob": b"AWS" + Plaintext, "KeyId": KeyId}
    def decrypt(self, CiphertextBlob, KeyId=None):  # noqa: N803
        assert CiphertextBlob.startswith(b"AWS")
        return {"Plaintext": CiphertextBlob[3:]}
    def describe_key(self, KeyId):  # noqa: N803
        return {"KeyMetadata": {"KeyId": KeyId}}


def test_awskms_custodian_roundtrip_with_fake_client():
    cust = AwsKmsCustodian(key_id="arn:test", client=_FakeKmsClient())
    root = AEAD.generate_key()
    env = cust.initialize(root)
    assert env.backend_id == "awskms"
    assert cust.unwrap(CustodyEnvelope.from_bytes(env.to_bytes())) == root


def test_awskms_rejects_foreign_envelope():
    cust = AwsKmsCustodian(key_id="arn:test", client=_FakeKmsClient())
    env = cust.initialize(AEAD.generate_key())
    env.backend_id = "gcpkms"
    with pytest.raises(RuntimeError):
        cust.unwrap(env)


# ----------------------------------------------------------------- GCP KMS ---

class _FakeGcpResp:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _FakeGcpClient:
    def encrypt(self, request):
        return _FakeGcpResp(ciphertext=b"GCP" + request["plaintext"])
    def decrypt(self, request):
        assert request["ciphertext"].startswith(b"GCP")
        return _FakeGcpResp(plaintext=request["ciphertext"][3:])


def test_gcpkms_custodian_roundtrip_with_fake_client():
    cust = GcpKmsCustodian(key_name="projects/p/locations/l/keyRings/r/cryptoKeys/k",
                           client=_FakeGcpClient())
    root = AEAD.generate_key()
    env = cust.initialize(root)
    assert env.backend_id == "gcpkms"
    assert cust.unwrap(CustodyEnvelope.from_bytes(env.to_bytes())) == root


# ----------------------------------------------------------------- PKCS#11 ---

class _FakeHsmWrapper:
    def wrap(self, plaintext):
        return b"HSM" + plaintext, {"iv_b64": "AAAA"}
    def unwrap(self, blob, metadata):
        assert blob.startswith(b"HSM") and metadata["iv_b64"] == "AAAA"
        return blob[3:]


def test_pkcs11_custodian_roundtrip_with_fake_wrapper():
    cust = Pkcs11Custodian(wrapper=_FakeHsmWrapper())
    root = AEAD.generate_key()
    env = cust.initialize(root)
    assert env.backend_id == "pkcs11"
    assert cust.unwrap(CustodyEnvelope.from_bytes(env.to_bytes())) == root
