# SPDX-License-Identifier: Apache-2.0
"""Generate the data-model reference (enums + relationship graph) from the source AST.

The data-model docs went stale because they were hand-maintained. This walks
``src/qureddy`` with the AST, extracts every class, enum, and typed field, and emits the
enum table plus a Mermaid class diagram of every relationship. Run it and paste the two
blocks into ``docs/architecture/data-model.md`` (or wire it into a CI check so the doc
cannot drift from the code again).

    python scripts/gen_data_model.py            # print both blocks
    python scripts/gen_data_model.py --enums    # just the enum table
    python scripts/gen_data_model.py --graph    # just the Mermaid diagram
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

_ENUM_BASES = {"Enum", "StrEnum", "IntEnum"}
_ROOT = Path(__file__).resolve().parent.parent / "src" / "qureddy"


def _base_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ast.unparse(node)


def _collect() -> dict[str, dict[str, object]]:
    classes: dict[str, dict[str, object]] = {}
    for path in sorted(_ROOT.rglob("*.py")):
        if "__pycache__" in str(path):
            continue
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError:
            continue
        module = str(path.relative_to(_ROOT)).replace("/", ".")[:-3]
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            bases = [_base_name(b) for b in node.bases]
            is_enum = any(b in _ENUM_BASES for b in bases)
            members: list[str] = []
            fields: list[tuple[str, str]] = []
            for stmt in node.body:
                if is_enum and isinstance(stmt, ast.Assign):
                    members += [t.id for t in stmt.targets if isinstance(t, ast.Name)]
                elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    fields.append((stmt.target.id, ast.unparse(stmt.annotation)))
            classes[node.name] = {
                "enum": is_enum,
                "members": members,
                "fields": fields,
                "module": module,
            }
    return classes


def _enum_table(classes: dict[str, dict[str, object]]) -> str:
    lines = ["| Enum | Module | Values |", "|---|---|---|"]
    for name, info in sorted(classes.items()):
        if not info["enum"]:
            continue
        values = ", ".join(f"`{m}`" for m in info["members"])  # type: ignore[union-attr]
        lines.append(f"| `{name}` | `{info['module']}` | {values} |")
    return "\n".join(lines)


def _graph(classes: dict[str, dict[str, object]]) -> str:
    import re

    names = set(classes)
    enums = {n for n, i in classes.items() if i["enum"]}
    edges: set[tuple[str, str, str, str]] = set()
    for name, info in classes.items():
        if info["enum"]:
            continue
        for _field, ftype in info["fields"]:  # type: ignore[union-attr]
            tokens = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", ftype))
            for target in (tokens & names) - {name}:
                many = any(c in ftype for c in ("tuple[", "list[", "frozenset[", "Mapping["))
                relation = "-->" if target in enums else "*--"
                edges.add((name, relation, target, "*" if many else ""))
    out = ["```mermaid", "classDiagram", "direction LR"]
    for enum in sorted(enums):
        out.append(f"class {enum} {{ <<enum>> }}")
    linked = {a for a, _, _, _ in edges} | {b for _, _, b, _ in edges}
    for name in sorted(names - enums):
        if name in linked:
            out.append(f"class {name}")
    for source, relation, target, many in sorted(edges):
        card = f' "{many}"' if many else ""
        out.append(f"{source} {relation}{card} {target}")
    out.append("```")
    return "\n".join(out)


def main() -> int:
    classes = _collect()
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    if arg == "--enums":
        print(_enum_table(classes))
    elif arg == "--graph":
        print(_graph(classes))
    else:
        print("## Enums\n")
        print(_enum_table(classes))
        print("\n## Relationship graph\n")
        print(_graph(classes))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
