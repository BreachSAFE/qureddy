# CBOM occurrence provenance grammar

Each CycloneDX crypto-asset component in a QuReddy CBOM attaches its observations as
`component.evidence.occurrences` (#287). Every occurrence carries an `additionalContext`
string that records how that observation was made. Since CycloneDX 1.7 gives an occurrence
no dedicated fields for scan provenance, QuReddy encodes it in `additionalContext` as a
strict, queryable `key=value` grammar (#307) rather than a prose sentence.

## Grammar

```
additionalContext := pair ("; " pair)*
pair              := key "=" value
key               := [a-z][a-z0-9_]*
value             := any text containing neither "; " nor "="
```

A consumer parses an occurrence with a total, two-step split:

```python
def parse(context: str) -> dict[str, str]:
    fields = {}
    for token in context.split("; "):
        key, _, value = token.partition("=")
        fields[key] = value
    return fields
```

No value contains `"; "` or `"="`, so this split never loses data.

## Fields

The pairs are emitted in this order. Only `observation` and `evidence_type` are always
present; the rest appear when the underlying evidence carries them.

| Key | Always | Meaning |
|---|---|---|
| `observation` | yes | Observation type: `negotiated`, `offered`, `observed`, `not_offered`, `not_testable`. |
| `evidence_type` | yes | Source signal, e.g. `tls.negotiation`, `tls.legacy.cipher`, `ssh.kex`. |
| `role` | when probed | Probe role, e.g. `hybrid_readiness`, `classical_control`. |
| `expected` | when probed | Group the probe forced, e.g. `X25519MLKEM768`. |
| `return_code` | when probed | Probe process exit code. |
| `command_sha256` | when probed | SHA-256 over the probe command. Attributed by executable basename, so it stays byte-stable across hosts and in `--reproducible` (#207). |
| `duration_ms` | non-reproducible only | Probe wall-clock time. Omitted under `--reproducible` (#162). |

## Example

```
observation=negotiated; evidence_type=tls.negotiation; role=hybrid_readiness; expected=X25519MLKEM768; return_code=0; command_sha256=25b212e8621b880aeb82ad7143dfb3ba93c4553d9618a6f4c9367e7880e364e1
```

The minimal form, for a signal with no probe record:

```
observation=offered; evidence_type=ssh.cipher
```

## Stability

This grammar is a supported output contract. A consumer that keyed on the previous prose
form (`"<observation> on <evidence_type> (...)"`) must migrate to the split-and-partition
parse above. The producer is `qureddy.output.cbom_metadata.evidence_occurrences`.
