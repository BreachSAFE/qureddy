# Local release gate

The repository-owned release gate is the authority for candidate artifacts. Run it from a
clean checkout with Python 3.12 or newer:

```console
python scripts/release_gate.py
```

The command downloads checksum-pinned `uv`, Gitleaks, and CycloneDX CLI binaries for the
current supported platform. It creates an isolated environment, runs every blocking local
check, builds one wheel and one sdist, inspects and clean-installs those exact bytes, and
writes `dist/release-evidence/manifest.json`.

A failed or timed-out gate exits nonzero and still writes a machine-readable failure
manifest. Live public-network probes, OpenSSL provisioning, the hosted CI mirror, and
repository protection settings are separate parts of issue
[#34](https://github.com/breachsafe/qureddy/issues/34); they are not hidden inside this
local command.
