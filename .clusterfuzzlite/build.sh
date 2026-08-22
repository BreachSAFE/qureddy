#!/bin/bash -eu
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
#
# ClusterFuzzLite / OSS-Fuzz build script for QuReddy's Atheris harnesses (#86).
# Runs inside the base-builder-python image (see .clusterfuzzlite/Dockerfile),
# with $SRC/qureddy as the working directory and $OUT as the fuzzer output dir.

# Install the package so the harnesses can import qureddy.* at fuzz time.
#
# --ignore-requires-python (#361): the OSS-Fuzz base-builder-python image ships
# Python 3.11 with Atheris built against it, but pyproject declares
# requires-python ">=3.12", so a plain install aborts with
# "requires a different Python: 3.11.x not in '>=3.12'" and NO fuzz target ever
# builds (also the Scorecard "Fuzzing" detection gap, #333). The fuzzed parsers
# (tls.parse, cert_sig, ssh.probe, core.targets) use no 3.12-only syntax and are
# verified to import and run on 3.11, so ignoring the marker is safe here. This
# is interim: once #327 moves the toolchain to 3.14 (atheris>=3.1 cp314, #325)
# the base image and runtime share an interpreter and this flag goes away.
pip3 install --no-cache-dir --ignore-requires-python .

# Package each tests/fuzz/fuzz_*.py harness into a standalone libFuzzer target.
# compile_python_fuzzer is provided by the OSS-Fuzz base image; it bundles the
# harness and its dependencies with Atheris coverage instrumentation.
for harness in tests/fuzz/fuzz_*.py; do
  compile_python_fuzzer "$harness"
done
