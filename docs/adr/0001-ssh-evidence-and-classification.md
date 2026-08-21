# ADR 0001: SSH evidence and classification doctrine

This record captures where SSH host-key inventory and weak-primitive
classification sit relative to QuReddy's honest-evidence charter, so the team
can ratify the current and extended behaviour. It is the first ADR in the base
(canonical) QuReddy repository.

## Contents

1. [Status](#1-status)
2. [Context](#2-context)
3. [Decision](#3-decision)
4. [Consequences](#4-consequences)
5. [Alternatives](#5-alternatives)

## 1. Status

Proposed. Awaiting team ratification.

- Supersedes: none.
- Related: #143 (emit SSH host keys in CBOM, widen weak-primitive detection),
  #37 (SSH scanner depth vs. `ssh-audit`).

## 2. Context

QuReddy is the base, source-available (Apache-2.0) PQC readiness scanner. Its
charter is to report **facts and evidence** — what a target positively offers or
negotiates — and honest readiness observations derived directly from those
facts. Deeper **compliance interpretation** (policy verdicts, framework mapping,
"pass/fail against control X") belongs to Qurum / the Enterprise track. This ADR
locates SSH host-key inventory and weak-primitive labelling relative to that
boundary.

### What ships today (on `main`)

`qureddy scan ssh` already reads and classifies SSH posture from the cleartext
KEXINIT exchange, with no crypto and no external binary:

- **Probe.** `src/qureddy/scanners/ssh/probe.py` (`read_kexinit_offer`) returns
  an `SSHOffer` carrying `kex_algorithms` and `host_key_algorithms` — the
  server's offered name-lists (capability, not a negotiated result).
- **Classification.** `src/qureddy/scanners/ssh/classify.py` holds pure
  functions over those name-lists. `weak_host_keys` /
  `weak_host_key_reasons` flag the deprecated host-key families in
  `_WEAK_HOST_KEY_NOTES`: `ssh-dss` (DSA, fixed 1024-bit, off by default since
  OpenSSH 7.0) and `ssh-rsa` (SHA-1 signature per RFC 8332, off by default since
  OpenSSH 8.8), plus their `-cert-v01@openssh.com` variants. `pq_hybrid_kex`
  detects `mlkem768x25519` / `sntrup761x25519` hybrids.
- **Rollup.** `src/qureddy/scanners/ssh/scanner.py` turns classification into
  `Finding`s with a `readiness` and rolls them up by a fixed precedence
  (`_PRECEDENCE`). `_weak_host_key_observation` emits a `ssh.hostkey.weak`
  finding at `Readiness.CLASSICALLY_WEAK`; `_kex_observation` emits either
  `ssh.kex.hybrid_offered` (`Readiness.TRANSITIONAL_HYBRID`) or
  `ssh.kex.classical_only` (`Readiness.QUANTUM_VULNERABLE`).

So base QuReddy **already** performs weak-primitive classification and readiness
rollup for SSH — and it does the same for TLS. This is established behaviour, not
a new capability.

### The gap #143 closes

Two SSH depth gaps were benchmarked against `ssh-audit` under #37:

1. **Host keys were dropped from the CBOM.** The CBOM algorithm emitter
   (`add_algorithm_components` in `src/qureddy/output/cbom_components.py`) only
   creates a `cryptographic-asset` component from `evidence.negotiated_group`,
   which the SSH path sets **only** for an offered PQ-hybrid KEX. Every observed
   host-key algorithm was therefore absent from the inventory that feeds Qurum,
   even though the console table and JSON already showed it. #143 records each
   offered host-key algorithm as `ssh.hostkey` evidence in the scanner and adds
   `src/qureddy/output/cbom_ssh.py` (`add_ssh_host_key_components`), which turns
   each into a signature-classified `cryptographic-asset` component — honestly
   classified as classical (`nistQuantumSecurityLevel` 0, the correct level for
   every current SSH host-key family). This mirrors how the TLS path emits its
   algorithm assets.
2. **Weak detection was host-key-only.** #143 extends the existing weak pattern
   from host keys to the KEX name-list the probe already collects, via
   `weak_kex` / `weak_kex_reasons` and a new `_WEAK_KEX_NOTES` table in
   `classify.py`: `diffie-hellman-group1-sha1` (1024-bit MODP + SHA-1),
   `diffie-hellman-group14-sha1`, `diffie-hellman-group-exchange-sha1`, and
   `rsa1024-sha1` (RFC 4432) now raise a `ssh.kex.weak` finding at
   `Readiness.CLASSICALLY_WEAK`. Cipher/MAC weaknesses (arcfour, hmac-md5) stay
   out of scope because the KEXINIT probe does not collect those name-lists.

Both additions read name-lists the probe **already** collects. Neither adds a
new probe, a network side effect, or a policy verdict — a `ssh.kex.weak` finding
is the same shape of honest observation as the `ssh.hostkey.weak` finding that
already ships.

### The doctrine tension

The question for ratification: does emitting a full host-key inventory and
labelling a KEX algorithm "weak" cross from *evidence* into *compliance
interpretation* that should live in Qurum / Enterprise?

- **Inventory** (every offered host-key algorithm as a CBOM component) is
  squarely evidence: it is the positively observed name-list, recorded verbatim,
  with an honest signature classification. Dropping it was an emitter accident,
  not a scope decision — the data was already collected and displayed.
- **Weak labelling** is the closer call. Calling `ssh-rsa` or
  `diffie-hellman-group1-sha1` "weak" is a value judgement. But it is a
  judgement base QuReddy **already makes** — for weak SSH host keys, and for the
  parallel TLS classifications — and it is grounded in vendor and RFC facts
  (off-by-default in OpenSSH; SHA-1 deprecation in RFC 8332; small-group
  transport). The line QuReddy holds is: *readiness observations about the
  cryptographic primitive itself* (weak / classical / transitional-hybrid /
  quantum-vulnerable) are evidence; *policy verdicts against a named control or
  framework* ("fails CIS 5.2", "non-compliant with BOD 25-01") are compliance
  interpretation and belong downstream.

## 3. Decision

**Proposed for ratification:** adopt **Option A**.

### Option A — Ratify the existing and extended behaviour (recommended)

Ratify that SSH host-key inventory **and** primitive-level weak/readiness
classification — including the #143 weak-KEX extension — are within base
QuReddy's honest-evidence charter, on the same footing as the TLS scanner.

Rationale:

- **TLS/SSH consistency.** Base QuReddy already emits weak/readiness
  classifications for TLS and for SSH host keys. Treating the SSH KEX name-list
  differently would be an inconsistent, surprising boundary for the same class
  of fact. `ssh.kex.weak` is the KEX-list analogue of the `ssh.hostkey.weak`
  finding already on `main`.
- **It is evidence, not policy.** Every label is a property of the observed
  primitive (bit size, hash family, vendor default state), cited to an RFC or a
  documented OpenSSH default. No finding names a compliance framework, control
  ID, or organisational policy.
- **The inventory gap was a bug.** Host keys were collected and shown but lost
  before the CBOM. Emitting them restores fidelity between what QuReddy observes
  and what it exports to Qurum; it does not add interpretation.
- **Downstream still owns compliance.** Qurum consumes the richer, honest CBOM
  and applies framework mapping and pass/fail verdicts. A more complete evidence
  base makes Qurum's interpretation better, without base QuReddy taking on that
  role.

Under Option A the boundary is stated explicitly (see Consequences) so future
SSH work stays on the evidence side of the line.

### Option B — Keep inventory in base, move weak-KEX *labelling* to Qurum

Emit the host-key and KEX inventory as neutral `cryptographic-asset` components
in base (evidence only), but do **not** raise `ssh.kex.weak` findings or roll a
`CLASSICALLY_WEAK` readiness from KEX in base. Let Qurum / Enterprise apply the
"weak" label from the exported inventory.

Trade-offs:

- **For:** draws the evidence/interpretation line more strictly — base reports
  *what was offered*, downstream decides *what is weak*. Keeps all value
  judgements in one place.
- **Against — inconsistency.** Base already labels weak SSH **host keys** and
  weak TLS primitives. Option B would either (a) leave that existing behaviour in
  place and treat KEX inconsistently, or (b) require **removing** shipped
  `ssh.hostkey.weak` / TLS classifications too — a regression to the honest
  readiness signal users already rely on, and a behaviour change beyond #143.
- **Against — usefulness.** A base-only user (no Qurum) would lose the "this KEX
  is weak" readiness signal that the tool is positioned to give, while still
  seeing weak host keys flagged — a confusing partial answer.
- **Against — the label is still needed somewhere.** The RFC/vendor facts that
  justify "weak" are the same wherever the label is applied; moving them
  downstream duplicates the classification table without changing its content.

Option B is presented so the team can weigh a stricter boundary; the
recommendation is Option A because base already sits on the "readiness
classification is evidence" side for both protocols and #143 only makes SSH
consistent with that.

## 4. Consequences

If Option A is ratified:

- The evidence/interpretation boundary for SSH is recorded as: **primitive-level
  readiness classification (weak / classical / transitional-hybrid /
  quantum-vulnerable), cited to RFC or documented vendor default, is base-QuReddy
  evidence; policy/framework verdicts are Qurum / Enterprise.** New SSH findings
  must stay on the evidence side of that line.
- The CBOM that feeds Qurum gains full SSH host-key inventory
  (`add_ssh_host_key_components`, `src/qureddy/output/cbom_ssh.py`) and
  `ssh.kex.weak` findings; Qurum's parser fixtures should cover the new
  signature-classified host-key components and the widened weak set.
- Base QuReddy and the TLS/SSH scanners stay behaviourally consistent: one class
  of honest readiness labelling across both protocols.
- No new probe, network behaviour, or external dependency is introduced; #143
  reads only name-lists already collected by `read_kexinit_offer`.

If Option B were chosen instead, the team accepts a behaviour change (removing or
withholding weak-KEX labelling, and reconciling it with already-shipped weak
host-key / TLS labels) and a base-only usability regression, in exchange for a
stricter evidence/interpretation split.

## 5. Alternatives

| Alternative | Summary | Why not (for now) |
|---|---|---|
| **A. Ratify existing + #143 extension** (recommended) | Host-key inventory in CBOM; `ssh.kex.weak` + readiness in base, consistent with TLS and existing SSH host-key flagging. | Chosen: consistent, evidence-grounded, no new interpretation. |
| **B. Inventory in base, weak-KEX label in Qurum** | Base emits neutral inventory only; Qurum applies "weak". | Inconsistent with shipped weak host-key / TLS labels; base-only usability regression; label facts unchanged by moving them. |
| **C. Expand weak detection to cipher/MAC name-lists** | Also flag arcfour, hmac-md5, etc. | Out of scope: the KEXINIT probe does not collect those name-lists. Would require new probing; revisit as its own change. |
| **D. Emit compliance verdicts in base** (e.g. framework pass/fail) | Base maps findings to CIS/BOD controls. | Explicitly rejected: that is Qurum / Enterprise's role; violates the OSS-scope boundary. |

References: #143, #37. Code cited above: `src/qureddy/scanners/ssh/probe.py`,
`src/qureddy/scanners/ssh/classify.py`, `src/qureddy/scanners/ssh/scanner.py`,
`src/qureddy/output/cbom_components.py`, `src/qureddy/output/cbom_ssh.py`.
