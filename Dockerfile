# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS openssl-build

ARG OPENSSL_VERSION=3.5.7
ARG OPENSSL_SHA256=a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates curl perl \
    && rm -rf /var/lib/apt/lists/*

RUN curl --fail --location --proto '=https' --connect-timeout 30 --max-time 300 \
      "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
      --output /tmp/openssl.tar.gz \
    && echo "${OPENSSL_SHA256}  /tmp/openssl.tar.gz" | sha256sum --check --strict \
    && mkdir /tmp/openssl-src \
    && tar --extract --gzip --strip-components=1 --file /tmp/openssl.tar.gz --directory /tmp/openssl-src \
    && cd /tmp/openssl-src \
    && ./Configure --prefix=/opt/openssl --openssldir=/opt/openssl/ssl shared no-tests \
    && make -j"$(nproc)" build_libs \
    && make -j"$(nproc)" apps/openssl \
    && make install_sw \
    && rm -rf /tmp/openssl.tar.gz /tmp/openssl-src

# Build the wheel from source inside the image (#253) so a fresh `docker build .`
# needs no host-built dist/ artifact. hatchling reads the static version from
# pyproject.toml, so the wheel version is intrinsic to the source, not an ARG.
FROM python:3.12.13-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b AS wheel-build
RUN pip install --no-cache-dir build==1.3.0 hatchling==1.31.0
WORKDIR /src
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY LICENSES/ ./LICENSES/
COPY src/ ./src/
RUN python -m build --wheel --no-isolation --outdir /tmp/wheel

FROM python:3.12.13-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b

ARG QUREDDY_VERSION=0.2.33
LABEL org.opencontainers.image.title="QuReddy" \
      org.opencontainers.image.description="Post-quantum readiness scanner for TLS and SSH endpoints" \
      org.opencontainers.image.source="https://github.com/breachsafe/qureddy" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${QUREDDY_VERSION}"

COPY --from=openssl-build /opt/openssl /opt/openssl

ENV QUREDDY_OPENSSL=/opt/openssl/bin/openssl \
    LD_LIBRARY_PATH=/opt/openssl/lib64:/opt/openssl/lib \
    PATH=/opt/openssl/bin:$PATH

RUN addgroup --gid 1000 qureddy \
    && adduser --uid 1000 --gid 1000 --disabled-password --gecos "" qureddy \
    && mkdir -p /var/lib/qureddy \
    && chown qureddy:qureddy /var/lib/qureddy

# Install the wheel built in the wheel-build stage (#253). That stage emits
# exactly one wheel, so /tmp/wheel/*.whl is unambiguous.
#
# Pinned-Dependencies (issue #221, #37): OpenSSF Scorecard treats a local
# `pip install <wheel>.whl` as its pinned form, but only when the install
# argument is a SINGLE literal ending in `.whl`. Scorecard's Dockerfile shell
# parser (extractCommand) drops any word made of more than one part, so a
# `pip install .../breachsafe_qureddy-${QUREDDY_VERSION}-*.whl` (literal
# + ${ARG} expansion + glob = 3 parts) would be discarded entirely, leaving a
# bare `pip install` that scores Pinned-Dependencies 9/10 ("dependency not
# pinned by hash"). Installing via a single-part literal glob (`/tmp/wheel/*.whl`,
# no ARG expansion) keeps that word intact, so Scorecard scores 10/10. The wheel
# is a local build artifact from an earlier stage, not a remote download.
#
# QUREDDY_WHEEL_SHA256 (optional) additionally gates the install on the wheel's
# sha256 for artifact integrity; a plain `docker build` without it still builds
# and still scores Pinned-Dependencies 10/10.
ARG QUREDDY_WHEEL_SHA256=""
COPY --from=wheel-build /tmp/wheel/*.whl /tmp/wheel/
RUN set -eu; \
    wheel="$(ls /tmp/wheel/*.whl)"; \
    if [ -n "${QUREDDY_WHEEL_SHA256}" ]; then \
      echo "${QUREDDY_WHEEL_SHA256}  ${wheel}" | sha256sum --check --strict; \
    fi; \
    pip install --no-cache-dir /tmp/wheel/*.whl; \
    rm -rf /tmp/wheel

USER qureddy
WORKDIR /var/lib/qureddy
ENTRYPOINT ["qureddy"]
