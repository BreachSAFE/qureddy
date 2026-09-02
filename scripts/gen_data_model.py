# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Generate checked data-model reference sections from the QuReddy source AST.

The generator owns two bounded sections in ``docs/architecture/data-model.md``:
the enum table and the annotated-field relationship graph. It declares every
class discovered under ``src/qureddy`` and rejects duplicate class names rather
than silently dropping one.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

_ENUM_BASES = frozenset({"Enum", "IntEnum", "StrEnum"})
_COLLECTION_TYPES = ("frozenset[", "list[", "Mapping[", "tuple[")
_REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
_SOURCE_ROOT = _REPOSITORY_ROOT / "src" / "qureddy"
_DOCUMENT = _REPOSITORY_ROOT / "docs" / "architecture" / "data-model.md"
_ENUM_START = "<!-- BEGIN GENERATED: enum-table -->"
_ENUM_END = "<!-- END GENERATED: enum-table -->"
_GRAPH_START = "<!-- BEGIN GENERATED: class-graph -->"
_GRAPH_END = "<!-- END GENERATED: class-graph -->"


@dataclass(frozen=True, slots=True)
class ClassInfo:
    """Describe one class declaration extracted from a source module."""

    name: str
    module: str
    is_enum: bool
    members: tuple[str, ...]
    fields: tuple[str, ...]


def _base_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ast.unparse(node)


def _module_name(path: Path) -> str:
    relative = path.relative_to(_SOURCE_ROOT).with_suffix("")
    return ".".join(relative.parts)


def _render_enum_value(node: ast.expr) -> str:
    try:
        value = ast.literal_eval(node)
    except TypeError, ValueError:
        return ast.unparse(node)
    return json.dumps(value, sort_keys=True)


def _enum_members(node: ast.ClassDef) -> tuple[str, ...]:
    members: list[str] = []
    for statement in node.body:
        if not isinstance(statement, ast.Assign):
            continue
        rendered_value = _render_enum_value(statement.value)
        for target in statement.targets:
            if isinstance(target, ast.Name):
                members.append(f"{target.id} = {rendered_value}")
    return tuple(members)


def _annotated_fields(node: ast.ClassDef) -> tuple[str, ...]:
    return tuple(
        ast.unparse(statement.annotation)
        for statement in node.body
        if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name)
    )


def _collect() -> tuple[ClassInfo, ...]:
    classes: dict[str, ClassInfo] = {}
    for path in sorted(_SOURCE_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        module = _module_name(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if node.name in classes:
                previous = classes[node.name]
                message = f"duplicate class name {node.name!r}: {previous.module!r} and {module!r}"
                raise ValueError(message)
            is_enum = any(_base_name(base) in _ENUM_BASES for base in node.bases)
            classes[node.name] = ClassInfo(
                name=node.name,
                module=module,
                is_enum=is_enum,
                members=_enum_members(node) if is_enum else (),
                fields=_annotated_fields(node),
            )
    return tuple(classes[name] for name in sorted(classes))


def _enum_table(classes: Sequence[ClassInfo]) -> str:
    lines = [
        "| Enum | Module | Members and serialized values |",
        "|---|---|---|",
    ]
    for info in classes:
        if not info.is_enum:
            continue
        members = ", ".join(f"`{member}`" for member in info.members)
        lines.append(f"| `{info.name}` | `{info.module}` | {members} |")
    return "\n".join(lines)


def _graph(classes: Sequence[ClassInfo]) -> str:
    names = {info.name for info in classes}
    enums = {info.name for info in classes if info.is_enum}
    edges: set[tuple[str, str, str, str]] = set()
    for info in classes:
        if info.is_enum:
            continue
        for field_type in info.fields:
            tokens = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", field_type))
            for target in (tokens & names) - {info.name}:
                many = any(container in field_type for container in _COLLECTION_TYPES)
                relation = "-->" if target in enums else "*--"
                edges.add((info.name, relation, target, "*" if many else ""))

    output = ["```mermaid", "classDiagram", "direction LR"]
    for info in classes:
        suffix = " { <<enum>> }" if info.is_enum else ""
        output.append(f"class {info.name}{suffix}")
    for source, relation, target, many in sorted(edges):
        cardinality = f' "{many}"' if many else ""
        output.append(f"{source} {relation}{cardinality} {target}")
    output.append("```")
    return "\n".join(output)


def _replace_generated_section(document: str, start: str, end: str, content: str) -> str:
    if document.count(start) != 1 or document.count(end) != 1:
        message = f"expected exactly one generated section bounded by {start!r} and {end!r}"
        raise ValueError(message)
    before, remainder = document.split(start, maxsplit=1)
    _, after = remainder.split(end, maxsplit=1)
    return f"{before}{start}\n{content}\n{end}{after}"


def _render_document(classes: Sequence[ClassInfo]) -> str:
    document = _DOCUMENT.read_text(encoding="utf-8")
    document = _replace_generated_section(
        document,
        _ENUM_START,
        _ENUM_END,
        _enum_table(classes),
    )
    return _replace_generated_section(
        document,
        _GRAPH_START,
        _GRAPH_END,
        _graph(classes),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--enums", action="store_true", help="print the generated enum table")
    modes.add_argument("--graph", action="store_true", help="print the generated class graph")
    modes.add_argument(
        "--write", action="store_true", help="update the generated document sections"
    )
    modes.add_argument("--check", action="store_true", help="verify the document is current")
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    """Run the requested generation or drift-check mode."""
    options = _parser().parse_args(arguments)
    classes = _collect()
    if options.enums:
        print(_enum_table(classes))
        return 0
    if options.graph:
        print(_graph(classes))
        return 0

    rendered = _render_document(classes)
    if options.write:
        _DOCUMENT.write_text(rendered, encoding="utf-8")
        return 0
    if options.check:
        if rendered == _DOCUMENT.read_text(encoding="utf-8"):
            return 0
        print(
            "docs/architecture/data-model.md is stale; "
            "run `uv run --locked python scripts/gen_data_model.py --write`",
            file=sys.stderr,
        )
        return 1

    print(_enum_table(classes))
    print()
    print(_graph(classes))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
