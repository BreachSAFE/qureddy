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

FROM python:3.12.13-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b

ARG QUREDDY_VERSION=0.2.0
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

COPY dist/breachsafe_qureddy-*.whl /tmp/
RUN pip install --no-cache-dir /tmp/breachsafe_qureddy-*.whl \
    && rm -f /tmp/breachsafe_qureddy-*.whl

USER qureddy
WORKDIR /var/lib/qureddy
ENTRYPOINT ["qureddy"]
