# Threat model and scope

QuReddy is a read-only endpoint measurement tool. It assumes an authorized
operator and a trustworthy scanner host. It reports what its TLS and SSH
probes observe; it is not a penetration test, trust validator, or defensive
control.

## Contents

- [Operator assumptions](#operator-assumptions)
- [Scanner host assumptions](#scanner-host-assumptions)
- [Network assumptions](#network-assumptions)
- [Target assumptions](#target-assumptions)
- [In-scope protections](#in-scope-protections)
- [Out-of-scope threats](#out-of-scope-threats)
- [Privacy and data handling](#privacy-and-data-handling)
- [Report a vulnerability](#report-a-vulnerability)
- [Related documentation](#related-documentation)

## Operator assumptions

The operator:

- owns the target or has authorization to scan it;
- supplies the intended hostname, port, SNI, and collector path;
- understands that endpoint probes are visible in network and service logs;
- preserves the result's exit code and unknown states;
- applies remediation outside QuReddy.

QuReddy does not scan stealthily or discover targets automatically.

## Scanner host assumptions

The Python interpreter, installed package, dependencies, operating system,
network resolver, and selected OpenSSL binary are trusted.

TLS collector selection is explicit: `--openssl`, then `QUREDDY_OPENSSL`, then
`openssl` on `PATH`. A malicious or replaced binary can fabricate output or
execute with the operator's privileges. QuReddy checks capability and records
path, version, subprocess digests, and bounded excerpts; it cannot establish
the binary's supply-chain integrity at runtime.

SSH scanning does not run OpenSSL.

## Network assumptions

The network path:

- permits outbound TCP to the named target;
- does not transparently redirect the connection to a different endpoint;
- may contain firewalls, proxies, load balancers, or middleboxes that affect
  the observed result;
- may fail or change between probes.

A network attacker that can alter DNS or traffic can influence the
observation. QuReddy does not use an out-of-band endpoint identity channel.

## Target assumptions

TLS targets return protocol output that the supported OpenSSL collector can
parse. SSH targets return an SSH identification string and KEXINIT packet
within the configured timeout.

Malformed or conflicting responses become typed target or parse failures.
Target-controlled text is treated as untrusted data and is not evaluated as
code.

## In-scope protections

QuReddy provides:

- strict target parsing before network access;
- allowlisted URI schemes;
- explicit ports and bounded timeouts;
- subprocess argument vectors without a shell;
- bounded output excerpts and full output digests;
- typed failure and unknown states;
- standard output separation from diagnostics;
- no SSH authentication or session creation;
- CycloneDX semantic rejection of duplicate or dangling references and
  secret-like material.

These properties limit scanner behavior and preserve evidence. They do not
secure the target.

## Out-of-scope threats

QuReddy does not defend against:

- a compromised scanner host, Python environment, or selected OpenSSL binary;
- DNS, routing, or active network interception;
- endpoint compromise or deliberate deceptive responses;
- denial of service against the scanner or target;
- side-channel attacks on the scanner host;
- TLS or SSH vulnerability exploitation;
- decryption or key recovery;
- certificate path, trust, hostname, revocation, or transparency validation;
- complete application, source, binary, key, or certificate inventory;
- automated remediation or blocking.

Use a dedicated TLS vulnerability scanner for vulnerability assessment.
QuReddy's scope is post-quantum readiness evidence.

## Privacy and data handling

QuReddy makes no telemetry, analytics, update-check, or BreachSAFE service
connection. It connects to the target named by the operator.

Results can contain target names, IP addresses, ports, SNI, certificate
metadata, algorithm names, local tool paths, bounded subprocess excerpts, and
digests. Standard output, redirected files, logs, and artifacts remain under
operator control. Operators must protect them according to their target and
environment sensitivity.

## Report a vulnerability

Do not report a vulnerability in a public issue. Follow the private process in
[`SECURITY.md`](../../SECURITY.md).

Questions about expected scope or classification may use the public issue
tracker when they contain no sensitive target data.

## Related documentation

- [Why hybrid post-quantum](why-hybrid-pq.md)
- [Harvest now, decrypt later](hndl.md)
- [Failure categories](../reference/failure-categories.md)
- [Security policy](../../SECURITY.md)
