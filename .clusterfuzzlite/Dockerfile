# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
#
# ClusterFuzzLite build image for QuReddy's Atheris parser harnesses (issue #86).
# Based on the OSS-Fuzz Python base builder, which ships Atheris, the coverage
# instrumentation, and the `compile_python_fuzzer` helper build.sh relies on.
FROM gcr.io/oss-fuzz-base/base-builder-python

# Place the checkout in the OSS-Fuzz source workspace and install the build
# script ClusterFuzzLite invokes from $SRC.
COPY . $SRC/qureddy
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/qureddy
