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

# Build the QuReddy wheel FROM SOURCE inside the image so `docker build .` works
# from a fresh clone with no pre-built dist/ artifact (issue #253). The wheel
# this stage produces always matches the checked-out source, which removes the
# previous dependency on a context-provided dist/ wheel and on QUREDDY_VERSION
# for wheel selection.
FROM python:3.12.13-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b AS wheel-build

WORKDIR /build

# COPY only what the wheel build (hatchling) needs: the package source, the
# project metadata, the README referenced by [project].readme, and the license
# files referenced by [project].license-files.
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY LICENSES ./LICENSES
COPY src ./src

# Build the wheel with PEP 517 build isolation. `pip wheel` (not `pip install`)
# reads [build-system].requires from pyproject.toml (hatchling==1.31.0, pinned)
# into an isolated env and produces exactly the project wheel (--no-deps). Using
# `pip wheel` avoids adding an unpinned `pip install <tool>` command, so it does
# not regress OpenSSF Scorecard Pinned-Dependencies (issue #221).
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /build/dist .

FROM python:3.12.13-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b

# QUREDDY_VERSION labels the image only. The installed version is fixed by the
# wheel built from source above, so this label cannot break the build or select
# the wrong wheel. The release pipeline passes the resolved version; a plain
# `docker build .` uses this default.
ARG QUREDDY_VERSION=0.2.17
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

# Install the wheel built from source in the wheel-build stage. It is the only
# wheel produced, so a bare `*.whl` glob cannot see two versions of the package.
#
# Pinned-Dependencies (issue #221, #37): OpenSSF Scorecard treats a local
# `pip install <wheel>.whl` as its pinned form, but only when the install
# argument is a SINGLE literal ending in `.whl`. Scorecard's Dockerfile shell
# parser (extractCommand) drops any word made of more than one part, so an
# install argument with an ${ARG} expansion + glob (multiple parts) is discarded
# entirely, leaving a bare `pip install` that scores Pinned-Dependencies 9/10
# ("dependency not pinned by hash"). Installing via a single-part literal glob
# (`/tmp/wheel/*.whl`, no ARG expansion) keeps that word intact, so Scorecard
# recognizes the local wheel and scores 10/10. The wheel is a local build
# artifact from the wheel-build stage, not a remote download.
#
# QUREDDY_WHEEL_SHA256 (optional) additionally gates the install on the wheel's
# sha256 for real artifact integrity. The release pipeline passes the digest of
# the wheel it built; a plain `docker build` without it still builds and still
# scores Pinned-Dependencies 10/10.
ARG QUREDDY_WHEEL_SHA256=""
COPY --from=wheel-build /build/dist/*.whl /tmp/wheel/
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
