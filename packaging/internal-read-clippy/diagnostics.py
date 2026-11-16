"""Join transient Cargo diagnostics to Clippy's resolved lookup events.

This validates reporting completeness only. Callee identity always comes from
Clippy's DefId event; diagnostic prose is never parsed for operation identity.
"""
from pathlib import Path

LINTS = frozenset({"clippy::disallowed_methods", "clippy::disallowed_types", "clippy::disallowed_macros"})


class DiagnosticsError(ValueError):
    pass


def _file(value, root):
    if not isinstance(value, str) or not value:
        raise DiagnosticsError("diagnostic/event span has no source filename")
    path = Path(value)
    if not path.is_absolute():
        path = Path(root) / path
    return str(path.resolve())


def _span(value, root, *, diagnostic=False):
    if not isinstance(value, dict):
        raise DiagnosticsError("diagnostic/event span is not an object")
    names = ("file_name", "line_start", "column_start", "line_end", "column_end") if diagnostic else ("file", "line", "column", "end_line", "end_column")
    try:
        coordinates = tuple(value[key] for key in names[1:])
        if any(not isinstance(number, int) or isinstance(number, bool) or number < 1 for number in coordinates):
            raise DiagnosticsError("diagnostic/event span has invalid coordinates")
        if coordinates[2:] < coordinates[:2]:
            raise DiagnosticsError("diagnostic/event span ends before it begins")
        return (_file(value[names[0]], root), *coordinates)
    except KeyError as error:
        raise DiagnosticsError(f"diagnostic/event span lacks {error}") from error


def _selected(message, target):
    actual = message.get("target")
    if not isinstance(actual, dict):
        raise DiagnosticsError("Cargo compiler-message has no target object")
    try:
        return (
            str(Path(actual["src_path"]).resolve()) == target["source"]
            and actual["name"].replace("-", "_") == target["crate"]
            and sorted(actual["crate_types"]) == target["crate_types"]
        )
    except (KeyError, TypeError, AttributeError) as error:
        raise DiagnosticsError("malformed Cargo compiler target") from error


def validate_diagnostics(messages, target, rows, *, root):
    """Require a one-to-one span/lint/reason join for one selected target.

    Include exceptions have their own compiler identity/count checks and emit no
    ordinary warning. Every operation event, including independent journal
    restrictions, must join a diagnostic in force-warn collection. Matching is
    exact; duplicates and ambiguous joins fail instead of being deduplicated.
    """
    operations = []
    for row in rows:
        if row.get("kind") != "operation":
            continue
        lint = row.get("lint")
        reason = row.get("rule_reason")
        if lint not in LINTS or not isinstance(reason, str) or not reason:
            raise DiagnosticsError("lookup event lacks its configured lint/reason")
        operations.append((lint, _span(row.get("span"), root), reason))
    matched = set()
    diagnostic_count = 0
    for envelope in messages:
        if envelope.get("reason") != "compiler-message":
            continue
        message = envelope.get("message")
        if not isinstance(message, dict):
            raise DiagnosticsError("Cargo compiler-message has no diagnostic object")
        code = message.get("code")
        lint = code.get("code") if isinstance(code, dict) else None
        if lint not in LINTS or not _selected(envelope, target):
            continue
        spans = message.get("spans")
        children = message.get("children")
        if not isinstance(spans, list) or not isinstance(children, list):
            raise DiagnosticsError("malformed policy diagnostic spans/children")
        primary = [span for span in spans if isinstance(span, dict) and span.get("is_primary")]
        if len(primary) != 1:
            raise DiagnosticsError("policy diagnostic has no unique primary span")
        location = _span(primary[0], root, diagnostic=True)
        notes = {child.get("message") for child in children if isinstance(child, dict) and child.get("level") == "note" and isinstance(child.get("message"), str)}
        candidates = [index for index, operation in enumerate(operations) if operation[0] == lint and operation[1] == location and operation[2] in notes]
        if not candidates:
            raise DiagnosticsError("policy diagnostic has no matching resolved lookup event")
        if len(candidates) != 1:
            raise DiagnosticsError("ambiguous diagnostic/resolved lookup event join")
        index = candidates[0]
        if index in matched:
            raise DiagnosticsError("multiple policy diagnostics share one lookup event")
        matched.add(index)
        diagnostic_count += 1
    if len(matched) != len(operations):
        raise DiagnosticsError("resolved lookup event has no matching policy diagnostic")
    return {"operations": len(operations), "diagnostics": diagnostic_count}
