# Threat model and scope

QuReddy is a **read-only** TLS readiness scanner. This page documents what it assumes about the operator, the network, and the target — and what it does not try to defend against. Reading this before opening a security issue saves a round trip.

## Operator assumptions

QuReddy assumes the operator:

- **Owns or has authorization to scan the target.** QuReddy makes no attempt to scan stealthily. It opens TCP connections, completes TLS handshakes, and produces detectable signatures (the second probe especially — a server that just saw an `X25519MLKEM768` ClientHello and now sees an `X25519`-only ClientHello from the same source IP within milliseconds is being scanned, and any halfway-decent IDS will flag it). Run this against your own infrastructure or with explicit permission.

- **Trusts their local OpenSSL binary.** QuReddy invokes `openssl` as a subprocess. The path resolution order (`--openssl` → `QUREDDY_OPENSSL` → PATH) lets the operator pin a specific binary. If your `openssl` is malicious, QuReddy has no defense — and neither does anything else on your system. This is a normal Unix-tool assumption.

- **Trusts their Python interpreter and dependencies.** QuReddy is a Python 3.12+ package with declared deps (`typer`, `click`, `rich`, `pydantic`, `structlog`, `packaging`). Supply-chain compromise of any of these compromises QuReddy. The project tracks CVEs via `pip-audit` in CI per [`docs/contributors/coding-rules.md`](../contributors/coding-rules.md).

- **Reads the verdict.** A `quantum_vulnerable` finding is informational, not actionable by the tool. QuReddy does not attempt to remediate, alert, or block. It produces a report; the human acts on it.

## Network assumptions

QuReddy assumes the network path between the scanner and the target:

- **Allows outbound TLS to the target on the requested port.** Egress firewalls or proxies that intercept TLS will produce confusing results — middleboxes that downgrade or replace certificates will look like target misconfiguration in the output. Run from a network path you control.

- **Has acceptable latency for two sequential handshakes.** Each scan runs two probes (hybrid + classical) in sequence, each subject to `--timeout`. Pathological latency (>30s default) produces `target_connect_failed` or `tls_handshake_failed` even when the target is fine.

- **Does not actively MITM.** A network attacker who can intercept and modify TLS traffic between the scanner and the target can produce arbitrary readiness verdicts. QuReddy does not validate certificates against pinned roots or compare server responses against an out-of-band source of truth.

## Target assumptions

QuReddy assumes the target:

- **Speaks TLS 1.3.** Both probes use `-tls1_3`. A target that only supports TLS 1.2 will fail both probes and report `tls_handshake_failed`. This is intentional — hybrid PQ groups are TLS-1.3-only.

- **Will negotiate a single key exchange group per handshake.** Standard TLS 1.3 behavior. A non-conforming server that returns multiple group names or no group line at all produces `parse_no_group` or `parse_ambiguous`.

- **Will produce parseable `openssl s_client -brief` output.** The parser is grounded in real OpenSSL 3.5.6 behavior. A server whose handshake produces `-brief` output not seen in the test fixtures may produce unexpected categorization. New shapes get added to the test fixture suite per [`docs/contributors/agents/...`](../contributors/agents/) skill `write-test-fixture`.

## What QuReddy does not try to defend against

These are explicitly out of scope. Filing an issue for any of these will be closed as not-a-bug:

- **Active attackers on the network path** (TLS interception, BGP hijacking, DNS cache poisoning). QuReddy is a measurement tool, not a defensive tool. Defense is the target server's responsibility — QuReddy reports what it sees.

- **Compromised operator endpoint.** If the machine running `qureddy` is compromised, the attacker can replace the binary, modify the venv, intercept subprocess calls. There is no defense possible at the application layer for this.

- **Side-channel attacks against the scanner host.** Timing, power analysis, electromagnetic emanations from the scanner — out of scope. QuReddy is not a cryptographic implementation; it shells out to OpenSSL.

- **Adversarial targets crafting confusing responses.** A target server that deliberately produces malformed `-brief` output to crash or mislead the parser is treated the same as accidentally-malformed output: the parser categorizes the failure into one of the documented `FailureCategory` values and the scan exits 2. The parser does not execute target-controlled content; it pattern-matches against typed regexes against a string buffer.

- **Decrypting target traffic, recovering target keys, exploiting target vulnerabilities.** QuReddy is a readiness scanner, not a penetration testing tool. It will not produce SSL/TLS exploits. Use [`testssl.sh`](https://testssl.sh) or [`sslyze`](https://github.com/nabla-c0d3/sslyze) for vulnerability assessment.

- **Privacy of the target.** QuReddy logs target hostnames, IPs, ports, SNI values, and OpenSSL output excerpts. If you need privacy of who you scanned, redact at the operator boundary (don't share scan logs with third parties).

## What QuReddy does provide

- **Determinism.** Same input produces the same output (modulo the `scan_id` UUID and timestamps). The JSON shape is locked at `qureddy.scan.v1`.

- **Auditable invocations.** `qureddy scan tls TARGET -vvv` shows the exact `openssl` commands. JSON output always includes the `command.executable` and `command.args` per probe. Operators can reproduce a probe by hand from the JSON.

- **Forensic preservation.** SHA-256 of full stdout and stderr is recorded per probe even when only an excerpt is shown. The 4 KB excerpt is bounded; the hash lets a downstream consumer detect tampering or truncation.

- **Failure categorization.** Every nonzero outcome maps to a typed `FailureCategory` value. Scripts can branch deterministically without parsing strings.

- **Reproducible local capability check.** Capability detection runs `openssl version` and `openssl list -tls1_3 -tls-groups`. Operators can re-run those two commands by hand to verify the local environment matches what QuReddy reported.

## Privacy and telemetry

**No telemetry, ever.** QuReddy makes no outbound connections except to the targets the operator specifies. There is no analytics SDK, no auto-update check, no error reporting service, no usage statistics. The dependency list ([`pyproject.toml`](../../pyproject.toml)) is auditable; `pip-audit` runs in CI.

The only data QuReddy collects is what the operator explicitly asked it to scan. That data goes to stdout (and, with `-v`+, to stderr). Where it goes after that is the operator's choice.

## Reporting security issues

Genuine security issues — vulnerabilities in the scanner that allow attacker-controlled execution, secrets disclosure, or scope escape — should follow [`SECURITY.md`](../../SECURITY.md). Behavioral questions ("does the scanner protect against X") should be filed as GitHub issues using the question template.

## Related

- [Why hybrid post-quantum?](why-hybrid-pq.md) — the cryptographic design QuReddy probes for
- [Harvest now, decrypt later](hndl.md) — the threat model behind the migration timeline
- [`SECURITY.md`](../../SECURITY.md) — vulnerability disclosure process
- [`docs/contributors/coding-rules.md`](../contributors/coding-rules.md) — the security bar for code changes
