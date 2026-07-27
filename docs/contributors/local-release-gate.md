# Local release gate

The repository-owned release gate is the authority for candidate artifacts. Run it from a
clean checkout with Python 3.12:

```console
python scripts/release_gate.py
```

The command downloads checksum-pinned `uv`, Gitleaks, and CycloneDX CLI binaries for the
current supported platform. It creates an isolated environment, runs every blocking local
check, builds one wheel and one sdist, inspects and clean-installs those exact bytes, and
writes `dist/release-evidence/manifest.json`.

The `release-gate` GitHub Actions workflow is a thin mirror on Linux, macOS, and Windows:
it checks out full candidate history, selects Python 3.12, invokes this same command, and
uploads the manifest and exact candidate artifacts even when the command fails. It does
not carry a second release policy or replace a failed command with a hosted-only check.

A failed or timed-out gate exits nonzero and still writes a machine-readable failure
manifest. Public TLS probes and the real SSH self-scan run weekly or by explicit manual
dispatch as advisory signals; they never block a pull request. Those jobs use the same
checksum-verified OpenSSL 3.6.3 source build on Linux, macOS, and Windows. Public repository
protection settings are administered separately and follow
[coding-rules §27](coding-rules.md#section-27--branch-protection-and-merge-hygiene); they
are not hidden inside this local command.

## Secret-scan classification

The full-history Gitleaks scan has one reviewed false-positive classification in
`.gitleaks.toml`. Commit `72f3fa4d750a393460ac40348e71f4b6c717bbce` introduced an
OpenSSL parser-test requirement containing the label `Server Temp Key` followed by the
public TLS hybrid-group identifier `X25519MLKEM768`. The default `generic-api-key` rule
interprets the label's final word as a credential assignment. It is protocol fixture text,
not authentication material.

The exception uses `condition = "AND"` and must match the rule ID, full introducing commit,
documentation path, and exact fixture line. Broad path, rule, or value exceptions are not
accepted. `tests/test_release_gate.py` locks those predicates, and the release gate still
scans the complete Git history.
