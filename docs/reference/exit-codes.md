# Reference: Exit codes

The `qureddy` CLI uses POSIX exit codes to signal what happened. Scripts and CI pipelines should branch on the exit code, not on parsing stdout.

## Contents

1. [Applicability by scanner](#1-applicability-by-scanner)
2. [The codes](#2-the-codes)
3. [Why these values](#3-why-these-values)
4. [Worked examples](#4-worked-examples)
5. [Implementation note](#5-implementation-note)
6. [Related documentation](#6-related-documentation)

## 1. Applicability by scanner

Exit 3 is specific to `scan tls`, because the SSH scanner does not use
OpenSSL. `scan ssh` uses exits 0, 2, and 4; exit 70 remains the process-wide
last-resort internal-error code.

## 2. The codes

| Code | Name | Meaning | When it fires |
|---|---|---|---|
| **0** | `EXIT_OK` | Scan succeeded | Both probes ran, evidence parsed, summary built. The target may still be `quantum_vulnerable`; that's a finding, not a failure. |
| **2** | `EXIT_TARGET_FAILED` | Target scan failed | Probes ran but the target is unreachable, refused TLS, MTU-blackholed, parser-rejected, etc. The target's problem (or the network between you and it). |
| **3** | `EXIT_LOCAL_DEPENDENCY` | Local OpenSSL is missing or unsupported | `openssl` not found on PATH, or version below 3.5.7, or the binary doesn't list `X25519MLKEM768` as a TLS 1.3 group. Install OpenSSL 3.5.7 LTS and re-run. |
| **4** | `EXIT_USAGE` | Usage or configuration error | Bad flag value (e.g. `--format yaml`), unknown retry category, `--retries` without `--retry-on`, malformed target string. |
| **70** | `EXIT_INTERNAL_ERROR` | Internal qureddy bug | An unhandled exception escaped to `main()`'s last-resort catch (e.g., a programming error in qureddy itself, an unhandled dependency failure). **This is qureddy's problem, not yours.** Open an issue with the printed error message and a reproducer. Code 70 is BSD `sysexits.h` `EX_SOFTWARE`. |

## 3. Why these values

- **0 and non-zero is universal**; every shell, every CI runner, every script handles `if exit == 0` correctly.
- **2 for "the operation didn't succeed"** matches `grep` and most CLIs that distinguish "no match" (1) from "I failed" (2). QuReddy doesn't have a "no match" outcome; failure is always a real failure.
- **3 separates the operator's problem from the target's problem.** If your CI shows exit 3, you fix your runner image. If it shows exit 2, you investigate the target.
- **4 separates "you typed something wrong" from "the scan didn't work".** This is the same convention `git`, `ssh`, and `curl` use.
- **70 (BSD `sysexits.h` `EX_SOFTWARE`) is reserved for "qureddy itself crashed".** Without a distinct code, an internal bug exits 2 (target failed); indistinguishable from a real target problem. CI scripts that branch on exit 2 must be able to trust that 2 means the target, not qureddy.

## 4. Worked examples

### CI pipeline that fails on bad targets but tolerates infra hiccups

```bash
qureddy scan tls api.example.com --format json > scan.json
case $? in
  0)
    echo "PQ-ready"
    ;;
  2)
    echo "Target reachable but PQ scan failed; investigate"
    cat scan.json | jq -r '.summary.failure_category'
    exit 1
    ;;
  3)
    echo "Runner is misconfigured (OpenSSL too old or missing)"
    exit 1
    ;;
  4)
    echo "Bug in this script; bad CLI flags"
    exit 1
    ;;
  70)
    echo "Internal qureddy bug; open an issue at github.com/breachsafe/qureddy"
    exit 1
    ;;
esac
```

### Bash trap that distinguishes operator vs target problems

```bash
qureddy scan tls "$TARGET" --format json > scan.json
case $? in
  3) echo "::error::OpenSSL 3.5 LTS+ missing on this runner" ;;
  2) echo "::warning::Scan against $TARGET failed" ;;
  4) echo "::error::Bad flags in CI config" ;;
esac
```

## 5. Implementation note

The Typer-based CLI's `main()` wrapper translates Click's default `UsageError` exit code (Click's 2) to QuReddy's `EXIT_USAGE` (4) so usage errors never collide with the documented "target scan failed" exit code. This means you can run `qureddy` from any shell and get the documented codes; Click's defaults stay internal to Click.

If you invoke `qureddy.cli.app` directly from Python (skipping `main()`), you get Click's defaults instead. Use `qureddy.cli.main` if you need the documented exit codes from a Python wrapper.

## 6. Related documentation

- [Reference: CLI options](cli.md); what triggers exit 4
- [Reference: Failure categories](failure-categories.md); what triggers exit 2 and exit 3
- [How-to: Capture machine-readable output for CI](../how-to/json-output-for-ci.md); using exit codes in pipelines
