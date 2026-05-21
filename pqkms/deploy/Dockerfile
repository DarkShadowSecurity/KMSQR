# PQ-KMS container
# Builds liboqs from source for post-quantum support, then installs the Python app.
#
# LIBOQS_REF is pinned to a release tag for reproducibility and to ensure the
# build picks up the Kyber-timing-leak fix (GHSA-f2v9-5498-2vpp, patched 0.10.1)
# and is past the HQC-correctness bug (GHSA-gpf4-vrrw-r8v7). Override at build
# time only after auditing the new ref:
#   docker build --build-arg LIBOQS_REF=0.13.0 ...
FROM python:3.12-slim AS builder

ARG LIBOQS_REF=0.12.0

RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
      build-essential cmake ninja-build git ca-certificates libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN git clone --depth 1 --branch ${LIBOQS_REF} https://github.com/open-quantum-safe/liboqs.git \
    && cd liboqs && mkdir build && cd build \
    && cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local \
             -DBUILD_SHARED_LIBS=ON \
             -DOQS_BUILD_ONLY_LIB=ON \
             -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_ml_dsa_65" \
             .. \
    && ninja && ninja install \
    && ldconfig

FROM python:3.12-slim

# Copy liboqs shared library from builder
COPY --from=builder /usr/local/lib/liboqs* /usr/local/lib/
COPY --from=builder /usr/local/include/oqs /usr/local/include/oqs
RUN ldconfig

RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
      libssl3 tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r pqkms && useradd -r -g pqkms -d /var/lib/pqkms -m pqkms

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY LICENSE ./LICENSE
COPY NOTICES.md ./NOTICES.md

ENV PQKMS_DATA_DIR=/var/lib/pqkms \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN chown -R pqkms:pqkms /var/lib/pqkms
USER pqkms

EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).status==200 else 1)"]
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
