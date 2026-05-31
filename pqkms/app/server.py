# Copyright (c) 2026 DarkShadowSec LLC.
# Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
"""
Server launcher with optional native TLS / mTLS.

Run with `python -m app.server`. TLS is configurable:

  * PQKMS_TLS_CERT + PQKMS_TLS_KEY  → terminate TLS in-process (uvicorn).
  * PQKMS_TLS_CLIENT_CA             → additionally require + verify client certs
                                      (mutual TLS).

Native TLS uses the runtime's OpenSSL. PQC-hybrid TLS (X25519MLKEM768) needs
OpenSSL 3.5+, which the slim base image does not ship — so the DOCUMENTED
DEFAULT for post-quantum-protected transport is the reverse proxy (see
deploy/proxy/), and native TLS here covers classical TLS / mTLS for proxy-less
or internal deployments.
"""
from __future__ import annotations

import logging
import os
import ssl

import uvicorn

log = logging.getLogger("pqkms.server")


def _tls_kwargs() -> dict:
    cert = os.environ.get("PQKMS_TLS_CERT")
    key = os.environ.get("PQKMS_TLS_KEY")
    if not (cert and key):
        return {}
    kwargs = {"ssl_certfile": cert, "ssl_keyfile": key}
    client_ca = os.environ.get("PQKMS_TLS_CLIENT_CA")
    if client_ca:
        kwargs["ssl_ca_certs"] = client_ca
        kwargs["ssl_cert_reqs"] = ssl.CERT_REQUIRED  # mutual TLS
    return kwargs


def main() -> None:
    host = os.environ.get("PQKMS_HOST", "0.0.0.0")
    port = int(os.environ.get("PQKMS_PORT", "8080"))
    kwargs = _tls_kwargs()
    if kwargs:
        log.info(
            "starting with native TLS (mTLS=%s)",
            "on" if "ssl_ca_certs" in kwargs else "off",
        )
    else:
        log.info("starting without TLS (terminate TLS at the reverse proxy)")
    uvicorn.run("app.main:app", host=host, port=port, **kwargs)


if __name__ == "__main__":
    main()
