# Generic code hygiene — shared checklist (Modes 2 and 5)

Four categories that apply identically whether you're auditing someone else's diff
(Mode 2 — read-only, report findings) or checking your own uncommitted work before a
commit (Mode 5 — fix what you find). The checks are the same either way; only the
posture differs — see the calling mode's own file for which posture applies.

## Panics / unrecoverable aborts in production code paths

```bash
# Rust
grep -n 'unwrap()\|\.expect(\|panic!' src/**/*.rs
# Python
grep -rn 'assert ' src/ | grep -v 'tests/'
```

Library/production code paths generally shouldn't abort the whole process on a
recoverable condition — propagate a typed error instead. Test code is usually exempt;
check the repo's own convention on where the line is. In Rust specifically, flag
`.unwrap()` / `.expect()` / `panic!()` in library/production paths.

## Subprocess / shell-out calls outside the designated module

Most BQP repos that shell out at all confine it to exactly one module. Find that module
in the repo you're working in (grep for the existing `subprocess.run` / `Command::new`
call sites — there's usually exactly one file) and flag anything outside it:

```bash
grep -rn 'Command::new\|std::process' src/
grep -rn 'subprocess\.' src/
```

Then manually exclude hits inside the repo's own designated shim file (if it has one) —
don't bake that filename into the grep pattern, since it varies per repo and a stale
pattern silently stops matching after a rename. Also flag: string-form command
construction instead of list/argv form, missing timeouts, and `shell=True` (or
equivalent) — these are subprocess-safety issues, not just placement issues.

## Logging / stray output in code that's supposed to be silent

```bash
grep -n 'println!\|eprintln!\|print!\|dbg!' src/**/*.rs
grep -rn 'print(' src/
```

Library code that callers embed generally shouldn't write to stdout/stderr on its own —
the caller decides what's user-facing. Also flag log messages that interpolate
free-form strings instead of the repo's structured-logging convention, if it has one.

## Dead code, commented-out code, floating TODOs

```bash
grep -rn '^\s*//.*[a-z]\+(' src/**/*.rs   # commented-out code, rough heuristic
grep -rn 'TODO\|FIXME' src/ | grep -v '#[0-9]\|issue'
```

Flag commented-out code (delete it — version control remembers it) and TODOs with no
owner or issue reference attached. Do **not** flag missing docstrings on private
helpers unless the repo's convention requires them — check the convention rather than
applying a personal preference.
