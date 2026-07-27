# How to generate a CBOM

Use `--format cbom` with either scanner to write a CycloneDX Cryptography
Bill of Materials to standard output.

## TLS endpoint

TLS scanning requires OpenSSL 3.5 or newer:

```bash
qureddy scan tls example.com --format cbom > example-tls.cbom.json
```

## SSH endpoint

SSH scanning has no OpenSSL dependency:

```bash
qureddy scan ssh github.com --format cbom > github-ssh.cbom.json
```

QuReddy writes the CBOM document to stdout. Redirect it to a file as shown
above, and use the process exit code to distinguish a successful scan from a
target, local-dependency, usage, or internal failure.

## Format status before the first PyPI release

Current `main` emits CycloneDX 1.6. The planned first PyPI release is tracking
CycloneDX 1.7 modeling and independent final-byte conformance in public issues
[#31](https://github.com/breachsafe/qureddy/issues/31) and
[#32](https://github.com/breachsafe/qureddy/issues/32). Treat the emitted
document's `specVersion` as authoritative; do not assume the pending 1.7 work
has landed.

The CBOM reports observations made by QuReddy. It is not a claim of complete
cryptographic inventory, remote implementation identity, certificate trust,
or revocation validation.

## See also

- [CLI options](../reference/cli.md)
- [Exit codes](../reference/exit-codes.md)
- [Capture machine-readable output for CI](json-output-for-ci.md)
