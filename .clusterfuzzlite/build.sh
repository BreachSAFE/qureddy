#!/bin/bash -eu
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
#
# ClusterFuzzLite / OSS-Fuzz build script for QuReddy's Atheris harnesses (#86).
# Runs inside the base-builder-python image (see .clusterfuzzlite/Dockerfile),
# with $SRC/qureddy as the working directory and $OUT as the fuzzer output dir.

# Install the package so the harnesses can import qureddy.* at fuzz time.
pip3 install --no-cache-dir .

# Package each tests/fuzz/fuzz_*.py harness into a standalone libFuzzer target.
# compile_python_fuzzer is provided by the OSS-Fuzz base image; it bundles the
# harness and its dependencies with Atheris coverage instrumentation.
for harness in tests/fuzz/fuzz_*.py; do
  compile_python_fuzzer "$harness"
done
