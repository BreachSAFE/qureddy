# How you write Python for this project

This file covers Python-specific authoring rules only. Agent behavior rules (operating discipline, anti-patterns, the pre-response audit) live in `docs/AGENT_ANTIPATTERNS.md`. Project orientation lives in `CLAUDE.md`.

You are writing Python for BreachSAFE QuReddy OSS. Apache 2.0. Public GitHub repo. Codex reviews everything you produce. Hold yourself to these rules without exception.

---

## Scope discipline

You build exactly what was asked. Nothing more. No "I also added this nice feature." No "I noticed you didn't have X so I added it." No "I refactored this while I was here." If you see something that needs changing outside the scope of the task, you note it in the response as "out of scope, flagged for later" and move on. You do not act on it.

If the task is "write the TLS scanner module," you write the TLS scanner module. You do not also write the cert scanner because it would be easy. You do not also write a CLI command because it would be useful. You do not also write tests for things that aren't being modified. You finish the asked-for thing and stop.

If you finish the asked-for thing in 50 lines, you stop at 50 lines. You don't pad with helpers, abstractions, "future-proofing," or speculative interfaces. You ship the smallest thing that meets the spec.

---

## File and function size

**Functions:** 30 lines or fewer in normal cases. If a function is over 50 lines, you justify it in a comment or you split it.

**Files:** 300 lines or fewer in normal cases. If a file is over 400 lines, the abstraction is wrong. Split it.

**Modules:** One clear responsibility per module. Not "tls_helpers.py with miscellaneous things." Either it has a single coherent purpose or it gets split.

---

## Dependencies

You do not add dependencies casually. Every new dependency in `pyproject.toml` must:

- Replace at least 50 lines of code we would have written
- Be actively maintained (commit in last 12 months)
- Have a license compatible with Apache 2.0 (no GPL, no AGPL, no LGPL without justification)
- Be a name you recognize or have verified exists with a real maintainer

If you're tempted to add a dependency for a one-off task, write the 5 lines yourself instead.

---

## Type hints

Every public function gets type hints on every parameter and return value. mypy strict mode must pass. If a type is genuinely dynamic (rare), use `Any` explicitly with a comment explaining why, not implicit untyped code.

Use `from __future__ import annotations` at the top of every file so forward references work cleanly.

Prefer `pathlib.Path` over `str` for filesystem paths. Prefer `pydantic.BaseModel` over `dict` for structured data. Prefer `Enum` over string constants for fixed vocabularies.

---

## Error handling

You raise specific exceptions, not bare `Exception`. The project has an `errors.py` module; new error types go there.

You do not catch and swallow exceptions silently. Every `except` clause either re-raises, logs with structured context, or transforms into a domain error.

You do not use `print()` for errors. You use the project's logger.

You do not catch `Exception` broadly except at the CLI top level where it converts to a clean exit code and message.

---

## Testing

Every new function with non-trivial logic gets a test. "Non-trivial" means: branches, loops, parsing, classification, anything beyond a one-liner.

Tests use real fixtures captured from real outputs, not synthetic stubs. The OpenSSL probe tests use captured `openssl s_client` outputs in `tests/fixtures/openssl/`. The cert parser tests use real cert files in `tests/fixtures/certs/`.

Every test runs on every change. No skipped tests, no "smoke vs. integration" split, no `@pytest.mark.slow` exclusions, no `tests/integration/` directory that runs on a different schedule. The full suite runs on every PR and every local `pytest` invocation. Slow CI is acceptable; missing coverage is not.

Network-dependent tests are explicitly allowed and encouraged. Hitting real targets (Cloudflare, badssl.com, AWS endpoints) catches middlebox, MTU, SNI, and certificate-edge-case regressions that captured fixtures cannot.

To keep transient internet hiccups from masking signal, the test runner uses `pytest-rerunfailures`: each test gets up to 3 attempts with a 1-second delay before being declared failed. If a test still fails after retries, that is a real finding — investigate before re-running. Do not raise the retry count to mask a flaky test you wrote yourself; flakiness from non-determinism in your code is wrong and you fix it.

The retry knob is on the test runner, not on individual tests. No `@flaky` decorators, no per-test retry overrides. One retry policy for the whole suite.

Tests do not depend on time or test-ordering randomness.

---

## Naming

Names describe what the thing is, not how it's implemented. `parse_certificate_chain` not `cert_parser_func`. `TLSEvidence` not `TLSData`.

No abbreviations except universal ones (TLS, SSH, RSA, KEX, HMAC). Spell out everything else. `certificate` not `cert` in type names. `configuration` not `cfg` in module names. (Exception: standard Python conventions like `cls`, `self`, `cfg` for argparse Namespace.)

No `utils.py`, `helpers.py`, `common.py`. If something doesn't have a clear home, it doesn't belong yet.

---

## Imports

Imports go at the top of the file. No conditional imports inside functions except for genuinely lazy-loaded things (and document why).

Standard library, then third-party, then first-party, with blank lines between groups. ruff isort handles this; you do not fight it.

No `from x import *`. Ever. No exceptions.

No relative imports across modules (`from ..core import X`). Use absolute imports (`from qureddy.core import X`).

---

## Comments and docstrings

Every public class and function gets a docstring. Google-style. Includes Args, Returns, Raises sections where applicable.

Comments explain *why*, not *what*. The code says what. Comments say why.

No commented-out code. Ever. If it's not running, delete it. Git remembers.

No TODO comments without a tracking issue or `# TODO(reason): description` format. Floating TODOs become permanent technical debt.

No `# fmt: off`, no `# noqa: ...` without a specific rule code and a comment explaining why.

---

## Output and logging

The CLI produces three kinds of output:

1. Findings on stdout, formatted by the configured output adapter (Rich table by default, JSON if `--format json`).
2. Logs on stderr, formatted by the project logger.
3. Nothing else. No `print()` for debugging. No mixed stdout/stderr.

Log levels:
- **DEBUG:** Detailed flow, only useful when debugging
- **INFO:** Normal operation milestones
- **WARNING:** Unexpected but recoverable
- **ERROR:** Failure that prevents completing a scan
- **CRITICAL:** Never used in normal flow

You do not log secrets, credentials, full URLs with auth tokens, or full certificate contents. Cert subjects and SHA-256 fingerprints are fine. Cert PEM bodies are not.

---

## Subprocess discipline

All subprocess calls to `openssl` live in `scanners/tls/openssl_probe.py`. No other module in the codebase calls `subprocess.run` with `openssl`. The `scripts/check_subprocess_boundaries.py` script enforces this rule in CI; you do not violate it even if it would be convenient.

Subprocess calls always:
- Use `subprocess.run` (not `os.system`, not `subprocess.Popen` without explicit reason)
- Pass `args` as a list, never a shell string
- Set `timeout` explicitly (default 30 seconds for scans)
- Capture stdout and stderr
- Check returncode and handle non-zero explicitly
- Set `check=False` and inspect returncode manually (so we can capture stderr on failure)

You do not use `shell=True`. Ever.

---

## Distribution and platform support

QuReddy ships in two forms at v1.0 (see Roadmap in `CLAUDE.md`). Until v1.0, only the Python path exists; the Docker image and PyPI publish land together at v1.0. Do not add a `Dockerfile` during MVP 0.1 - 0.6.

1. Native Python package via `pipx install breachsafe-qureddy`. Works on macOS 14+, modern Linux distributions, and Windows 10 22H2+ (native Windows support lands in v1.0).

2. Container image at `ghcr.io/breachsafe/qureddy:latest`. Works on any host that runs Docker or Podman. Ships at v1.0.

Both paths target the same modern platforms. Neither path runs on EOL operating systems (Windows XP/7/8.1, RHEL 6, Ubuntu 16.04 and earlier).

If a customer's host can't run modern software, they install QuReddy on a separate modern machine and use it to scan their legacy hosts over the network. That's the supported workflow.

Code is written to work on both install paths. We do not assume Docker or pipx exclusively. Specifically:

- File paths use `pathlib.Path`, never hardcoded `/tmp` or `/usr/local`
- Subprocess calls find tools via `PATH`, not absolute paths
- Configuration locations are platform-aware (use `platformdirs` library)
- Tests run on both bare-metal Python and inside the Docker image

---

## Security hygiene

You do not write code that:
- Uses `eval()`, `exec()`, or `pickle.loads()` on untrusted input
- Reads or writes files with user-controlled paths without `pathlib.Path.resolve()` and validation
- Logs cryptographic material (keys, signatures, full certs)
- Disables TLS verification (`verify=False`, `ssl.CERT_NONE`) without an explicit threat model comment

You do use:
- `secrets` module for any randomness that has a security purpose
- `hmac.compare_digest` for any string comparison involving secrets
- `pathlib.Path.resolve()` for any user-supplied path
- Constant-time comparisons for any token check

---

## When you don't know

If you don't know how something should work, you say so explicitly. You do not make up an answer that sounds confident. You ask, or you flag the assumption clearly:

```
ASSUMPTION: I am assuming X because the spec is silent on it. If wrong, change to Y.
```

If you're about to invent a library, API, or function name that you're not 100% sure exists, you stop and verify. Hallucinated imports are the single biggest source of bugs in agentic code.

---

## What "done" means

A task is done when:

1. The asked-for functionality works
2. Tests pass
3. mypy strict passes
4. ruff check passes
5. The change is the smallest one that meets the spec
6. The diff is reviewable in 5 minutes by a human

Not when:
- All possible edge cases are handled
- All possible future features are scaffolded
- The code is "perfect"
- You've added "just one more thing"

When you finish a task, you respond with:

1. What you did (one paragraph)
2. The diff or new files
3. What you did NOT do that you considered (out-of-scope items, flagged for later)
4. Any assumptions you made
5. Any open questions for the human

---

## Things you do not do

You do not refactor unrelated code.

You do not add features that weren't requested.

You do not change file structure without explicit instruction.

You do not add dependencies without justification.

You do not write more than one file when one was asked for.

You do not write speculative abstractions for "future flexibility."

You do not generate boilerplate that isn't going to be used today.

You do not add metaclasses, decorators, or complex inheritance unless the spec explicitly requires them.

You do not use `*args` and `**kwargs` to "be flexible." Be specific about parameters.

You do not add comments that explain what the code obviously does.

You do not add `if __name__ == "__main__":` blocks to library modules.

---

## Voice in code

No marketing language in docstrings or comments. No "leverage," no "intersection of," no "robust enterprise-grade solution." Plain English. Same voice the rest of the project uses.

No em dashes anywhere, including in comments and docstrings.

No emoji in code, comments, or docstrings.

No ASCII art banners in source files.

---

## Voice in responses

When you respond to me with a code task, you:

1. Confirm you understand the task in one sentence
2. Note any ambiguity or assumption before coding
3. Produce the code
4. Summarize what you did and didn't do
5. Stop

You do not over-explain. You do not pad with "Let me know if you need anything else!" or "Hope this helps!" You do not narrate your thinking unless asked.

---

## When you disagree with the spec

If the spec is wrong or has a flaw, you say so directly before coding. You do not silently fix it. You do not silently ignore it. You name the issue, propose the fix, and wait for confirmation, or proceed with explicit assumption marker.
