# Evidence honesty

QuReddy reports a bounded network observation and its interpretation. It does
not convert missing data into favorable evidence or expand an endpoint
handshake into claims about the full remote system.

## Contents

- [Evidence layers](#evidence-layers)
- [Remote observation](#remote-observation)
- [Local collector capability](#local-collector-capability)
- [Scanner interpretation](#scanner-interpretation)
- [Unknown and not testable](#unknown-and-not-testable)
- [Offered and negotiated](#offered-and-negotiated)
- [Certificate boundary](#certificate-boundary)
- [Implementation identity boundary](#implementation-identity-boundary)
- [Standards and validation language](#standards-and-validation-language)
- [Platform support](#platform-support)
- [Consumer responsibilities](#consumer-responsibilities)
- [Related documentation](#related-documentation)

## Evidence layers

The result model separates:

| Layer | Question | Example |
| --- | --- | --- |
| Remote observation | What bytes or protocol choice did the endpoint expose? | SSH offered `sntrup761x25519-sha512` |
| Local capability | Could this scanner host perform the requested collection? | Local OpenSSL listed `X25519MLKEM768` |
| Interpretation | Which named rule applies to the observation? | `ssh.kex.hybrid_offered` |
| Unknown state | Which conclusion could not be established? | TLS posture is `not_testable` because OpenSSL is missing |

These layers remain separate in JSON and CBOM. A local dependency must not be
attributed to the remote endpoint, and a finding must reference the evidence
that supports it.

## Remote observation

TLS observations come from bounded OpenSSL handshakes and certificate parsing.
SSH observations come from the cleartext server identification and KEXINIT
offer. An observation states what the target returned to this probe at this
time.

Network observations are mutable. Load balancers, source address policies,
protocol negotiation, deployment changes, and transient failures can produce
different results from another location or time. A live result is evidence for
that run, not a permanent property of the service.

## Local collector capability

OpenSSL version, path, supported group list, process return code, and output
digests describe the local scanner host. They are collection provenance.

The selected OpenSSL version does not identify the remote TLS library. A
missing or unsuitable local binary produces exit `3` and a local capability
failure. It does not prove that the target lacks post-quantum support.

SSH collection does not use OpenSSL. An OpenSSL failure has no bearing on an
SSH result.

## Scanner interpretation

A finding is a rule interpretation linked to one or more evidence records. For
example, a recognized hybrid SSH key exchange offer produces
`ssh.kex.hybrid_offered` with readiness `transitional_hybrid`.

The interpretation is narrower than a compliance or security certification.
It answers the named readiness question under the shipped rule. Downstream
systems may apply separate policy, but they must preserve the source
observation and its unknown or failure state.

## Unknown and not testable

`unknown` means the available evidence cannot establish a readiness result.
`not_testable` records that collection did not occur or could not support the
claim.

Neither value means safe, vulnerable, absent, or compliant. Consumers must not
coerce either value into a pass.

A failed target can still yield partial evidence. For example, a certificate
probe may succeed while a forced key exchange probe fails. The output retains
both facts and the top-level failure category.

## Offered and negotiated

SSH KEXINIT exposes an offered algorithm list. QuReddy can state that a
recognized algorithm was offered, but it does not authenticate or negotiate
an SSH session.

TLS forced-group handshakes can record the group actually negotiated. An
offered legacy protocol or cipher suite and a negotiated TLS 1.3 group are
different observation types. Documentation and consumers must not use those
terms interchangeably.

## Certificate boundary

QuReddy observes and parses the leaf certificate returned by the target. It
can record names, dates, serial number, signature algorithm, public key
summary, and a signature-verified self-signed classification when the
necessary evidence is available.

The scanner does not perform:

- certificate path construction;
- trust store validation;
- hostname validation;
- revocation checks;
- Certificate Transparency verification;
- proof that the remote endpoint controls the corresponding private key
  beyond the observed protocol exchange;
- complete chain or key-size inventory.

Subject and issuer name equality is not proof that a certificate is
self-signed.

## Implementation identity boundary

Protocol behavior does not uniquely identify software. QuReddy does not infer
the remote OpenSSL, OpenSSH, operating system, vendor, package, or version from
a handshake.

In CycloneDX output, the remote endpoint is a generic application component.
QuReddy and local OpenSSL appear separately as collector tool provenance.

## Standards and validation language

CycloneDX conformance means the emitted final bytes passed the pinned schema,
independent CLI validator, and QuReddy semantic checks. It does not mean the
target is secure or compliant.

An observed algorithm name may align with a NIST standard. QuReddy does not
claim that the remote deployment, local OpenSSL build, or delivered Python
package is FIPS validated. Such a claim would require the applicable validated
module, certificate, version, platform, and configuration.

## Platform support

Supported means the wheel and source distribution installed and the documented
command surface ran in the release matrix for Linux, macOS, and Windows.

Supported does not mean:

- every operating system package repository includes OpenSSL 3.5 or newer;
- every network permits the target port;
- every target exposes the same posture from every source address;
- a planned container or hosted service exists.

## Consumer responsibilities

A consumer should:

- preserve raw JSON or CBOM bytes and the process exit code;
- distinguish local dependency, target failure, observation, and finding;
- retain `unknown` and `not_testable`;
- resolve evidence references before presenting a finding;
- label live observations with time and collection location when that context
  affects interpretation;
- avoid adding remote identity, trust, validation, or completeness claims that
  the artifact does not contain.

## Related documentation

- [JSON output](../reference/json-schema.md)
- [CycloneDX 1.7 CBOM](../reference/cbom.md)
- [Failure categories](../reference/failure-categories.md)
- [Threat model](threat-model.md)
- [Architecture](architecture.md)
