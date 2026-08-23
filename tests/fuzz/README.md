<!--
SPDX-FileCopyrightText: 2026 BreachSAFE
SPDX-License-Identifier: Apache-2.0
-->

# QuReddy parser fuzzing

Coverage-guided [Atheris](https://github.com/google/atheris) fuzz harnesses for
the parsers that consume untrusted external input: user-supplied target strings,
OpenSSL subprocess output, and the cleartext SSH `KEXINIT` a remote server
sends. This closes the OpenSSF Scorecard "Fuzzing" gap tracked in issue #86 and
extends the property-based coverage from issue #37 / #131.

## Contents

1. [Overview](#overview)
2. [Harnesses](#harnesses)
3. [Run a harness locally](#run-a-harness-locally)
4. [Atheris fuzzing in CI](#atheris-fuzzing-in-ci)

## Overview

`atheris` is an optional, fuzz-only dependency: it is not installed by the
normal `dev` extra or the release gate, and it builds only against
libFuzzer/Clang (Linux). The harness files are named `fuzz_*.py`, so `pytest`
never collects them, and every harness imports `atheris` behind a guard, so the
module still imports in an environment where `atheris` is absent. Each harness
asserts the same contract: for any input the parser either returns a valid
result or raises only its declared exception type, never an unhandled crash.

## Harnesses

| Harness | Parser under test | Declared exception |
| --- | --- | --- |
| `fuzz_target.py` | `qureddy.core.targets.parse_target` | `TargetParseError` |
| `fuzz_ssh_target.py` | `qureddy.core.targets.parse_ssh_target` | `TargetParseError` |
| `fuzz_tls_parse.py` | `qureddy.scanners.tls.parse.parse_brief_output` | none (total) |
| `fuzz_ssh_kexinit.py` | SSH packet framing + `KEXINIT` name-list parsing | `SSHProbeError` |
| `fuzz_cert_sig.py` | `qureddy.scanners.tls.cert_sig.parse_certificate_signature` | none (total) |

## Run a harness locally

Atheris requires Linux with Clang. Install the `fuzz` extra and run any harness
directly; pass libFuzzer flags after the harness name.

```bash
# Install the fuzz-only dependency group.
uv pip install --python 3.12 -e '.[fuzz]'

# Fuzz one parser for 60 seconds.
python tests/fuzz/fuzz_target.py -max_total_time=60

# Reproduce a crash from a saved input.
python tests/fuzz/fuzz_ssh_kexinit.py path/to/crash-input
```

## Atheris fuzzing in CI

Pull requests that touch the parsers, the harnesses, or the fuzzing setup run a
short, bounded Atheris session via `.github/workflows/cifuzz.yml`. The workflow
installs the Python 3.14 `atheris>=3.1` wheel on an amd64 Linux runner and runs
each harness for 45 seconds. This is the repository's PR-time fuzz check; it is
separate from the optional hosted Google OSS-Fuzz onboarding tracked in issue
#372.
