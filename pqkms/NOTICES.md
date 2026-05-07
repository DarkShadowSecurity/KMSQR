# Notices

## PQ-KMS

PQ-KMS itself is **proprietary software, copyright (c) 2026 DarkShadowSec
LLC, all rights reserved.** See the `LICENSE` file in this directory for
the governing terms. No license to use, copy, modify, or distribute the
original code in this repository is granted by this NOTICES file.

## Third-Party Components

PQ-KMS depends on the following third-party components. Each remains
governed by its own license, **independent of and unaffected by** the
proprietary license that covers the original PQ-KMS code. Verbatim
license texts are available at the upstream URLs cited below; for
redistribution that triggers notice obligations (e.g. binary distribution
of a container image), include the upstream LICENSE / NOTICE files.

| Component        | Version    | License                       | Source                                                 |
|------------------|------------|-------------------------------|--------------------------------------------------------|
| FastAPI          | 0.115.0    | MIT                           | https://github.com/fastapi/fastapi                     |
| uvicorn          | 0.32.0     | BSD-3-Clause                  | https://github.com/encode/uvicorn                      |
| pydantic         | 2.9.2      | MIT                           | https://github.com/pydantic/pydantic                   |
| cryptography     | 46.0.6     | Apache-2.0 OR BSD-3-Clause    | https://github.com/pyca/cryptography                   |
| argon2-cffi      | 23.1.0     | MIT                           | https://github.com/hynek/argon2-cffi                   |
| Argon2 reference | bundled    | Apache-2.0 / CC0              | https://github.com/p-h-c/phc-winner-argon2             |
| slowapi          | 0.1.9      | MIT                           | https://github.com/laurentS/slowapi                    |
| liboqs-python    | 0.14.1     | MIT                           | https://github.com/open-quantum-safe/liboqs-python     |
| liboqs (C lib)   | 0.12.0     | MIT (with subfolder licenses) | https://github.com/open-quantum-safe/liboqs            |
| Python (PSF)     | 3.12       | PSF License                   | https://docs.python.org/3/license.html                 |
| Debian slim base | bookworm   | mixed (GPL/MIT/BSD/...)       | https://www.debian.org/legal/licenses/                 |

## Notes

- **cryptography**: dual-licensed; Apache-2.0 is recommended for new redistributions
  because of its explicit patent grant. If a `NOTICE` file is shipped upstream,
  it must be preserved per Apache-2.0 §4(d).
- **liboqs**: while liboqs proper is MIT, it bundles third-party algorithm
  reference implementations under varying terms. The build in `deploy/Dockerfile`
  uses `OQS_MINIMAL_BUILD=KEM_ml_kem_768;SIG_ml_dsa_65`, which only includes
  upstream public-domain reference code. If `OQS_MINIMAL_BUILD` is widened,
  re-audit the included subfolder licenses at
  https://github.com/open-quantum-safe/liboqs/tree/main/src .
- **Debian base image**: distributing this container image to third parties
  triggers source-availability obligations for any GPL-licensed packages it
  includes. Generate an SBOM (e.g. with `syft` or `docker sbom`) and follow
  the Debian source distribution conventions if you redistribute.
- **No copyleft contamination**: every directly-imported runtime dependency
  is permissive (MIT / BSD / Apache / PSF / OFL).
