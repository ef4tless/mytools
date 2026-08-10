#!/usr/bin/env python3
"""Pure-Python, deterministic if-ladder to switch-view rewriter.

This module intentionally has no IDA imports.  It operates on Hex-Rays text
that has already had color tags removed.  The rewriter does not try to make
the decompiled program compile: it preserves Hex-Rays-specific expressions,
labels, gotos, named arguments, and local declarations as analysis evidence.
"""

from __future__ import annotations

import copy
import hashlib
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _strip_base(line: str, base: int) -> str:
    if not line.strip():
        return ""
    return line[base:] if _indent_of(line) >= base else line.lstrip()


def _norm_line(line: str) -> str:
    return re.sub(r"\s+", " ", line.strip())


def _parse_int(text: str) -> Optional[int]:
    value = text.strip().lower().replace("`", "")
    value = re.sub(r"(?:u|l)+$", "", value)
    try:
        if value.endswith("h") and re.fullmatch(r"[0-9a-f]+h", value):
            return int(value[:-1], 16)
        return int(value, 0)
    except ValueError:
        return None


_COND_RE = re.compile(
    r"^\s*\(?\s*([A-Za-z_]\w*)\s*(==|!=|>=|<=|>|<)\s*"
    r"(0x[0-9A-Fa-f]+|[0-9]+)(?:[uUlL]+)?\s*\)?\s*$"
)
_COND_RE_REVERSED = re.compile(
    r"^\s*\(?\s*(0x[0-9A-Fa-f]+|[0-9]+)(?:[uUlL]+)?\s*"
    r"(==|!=|>=|<=|>|<)\s*([A-Za-z_]\w*)\s*\)?\s*$"
)


def parse_simple_condition(condition: str) -> Optional[Tuple[str, str, int]]:
    match = _COND_RE.fullmatch(condition)
    if match:
        value = _parse_int(match.group(3))
        return (match.group(1), match.group(2), value) if value is not None else None
    match = _COND_RE_REVERSED.fullmatch(condition)
    if match:
        value = _parse_int(match.group(1))
        if value is None:
            return None
        reverse = {">": "<", ">=": "<=", "<": ">", "<=": ">=", "==": "==", "!=": "!="}
        return match.group(3), reverse[match.group(2)], value
    return None


def eval_simple_condition(condition: str, variable: str, value: int) -> Optional[bool]:
    parsed = parse_simple_condition(condition)
    if not parsed or parsed[0] != variable:
        return None
    _, operator, constant = parsed
    return {
        "==": value == constant,
        "!=": value != constant,
        ">": value > constant,
        ">=": value >= constant,
        "<": value < constant,
        "<=": value <= constant,
    }[operator]


@dataclass
class Node:
    def render(self, indent: int) -> List[str]:
        raise NotImplementedError


@dataclass
class RawNode(Node):
    lines: List[str]

    def render(self, indent: int) -> List[str]:
        prefix = " " * indent
        return [prefix + line if line else "" for line in self.lines]


@dataclass
class LabelNode(Node):
    name: str

    def render(self, indent: int) -> List[str]:
        # Hex-Rays prints function labels at column zero regardless of the
        # surrounding structured indentation.  Keeping that convention also
        # makes cross-case gotos obvious.
        return [self.name + ":"]


@dataclass
class IfNode(Node):
    condition: str
    then_body: List[Node]
    else_body: Optional[List[Node]] = None

    def render(self, indent: int) -> List[str]:
        prefix = " " * indent
        result = [prefix + "if ( " + self.condition.strip() + " )", prefix + "{"]
        result.extend(render_nodes(self.then_body, indent + 2))
        result.append(prefix + "}")
        if self.else_body is not None:
            result.extend([prefix + "else", prefix + "{"])
            result.extend(render_nodes(self.else_body, indent + 2))
            result.append(prefix + "}")
        return result


@dataclass
class SwitchCase:
    value: int
    action: str
    body: List[Node]


@dataclass
class SwitchNode(Node):
    variable: str
    cases: List[SwitchCase]
    default_body: List[Node]
    shared_label_sections: List[List[Node]]
    continuation_label: str
    continuation_is_synthetic: bool = False

    def render(self, indent: int) -> List[str]:
        prefix = " " * indent
        result = [prefix + "switch ( " + self.variable + " )", prefix + "{"]
        for case in self.cases:
            result.append(prefix + "case 0x%x: // %s" % (case.value, case.action))
            result.extend(render_nodes(case.body, indent + 2))
            if not _ends_control_transfer(case.body):
                result.append(" " * (indent + 2) + "break;")
        result.append(prefix + "default:")
        result.extend(render_nodes(self.default_body, indent + 2))
        if not _ends_control_transfer(self.default_body):
            result.append(" " * (indent + 2) + "break;")
        result.append(prefix + "}")
        if self.shared_label_sections:
            result.append(prefix + "goto " + self.continuation_label + ";")
            for section in self.shared_label_sections:
                result.extend(render_nodes(section, indent))
            if self.continuation_is_synthetic:
                result.append(self.continuation_label + ":")
        return result


@dataclass
class DispatchRegion:
    container: List[Node]
    start: int
    end: int

    @property
    def nodes(self) -> List[Node]:
        return self.container[self.start:self.end]


def render_nodes(nodes: Sequence[Node], indent: int) -> List[str]:
    result: List[str] = []
    for node in nodes:
        result.extend(node.render(indent))
    return result


def _last_code_line(nodes: Sequence[Node]) -> str:
    for node in reversed(nodes):
        lines = node.render(0)
        for line in reversed(lines):
            stripped = line.strip()
            if stripped and stripped not in ("{", "}") and not stripped.startswith("//"):
                return stripped
    return ""


def _ends_control_transfer(nodes: Sequence[Node]) -> bool:
    line = _last_code_line(nodes)
    return bool(re.match(r"(?:goto\b|return\b|break;|continue;|__builtin_unreachable)", line))


def _node_always_transfers(node: Node) -> bool:
    if isinstance(node, RawNode):
        # Multi-line RawNodes are preserved compound constructs such as loops.
        # A goto in one loop arm does not make the compound unconditionally
        # terminating, so only classify a single raw statement here.
        return len(node.lines) == 1 and _ends_control_transfer([node])
    if isinstance(node, IfNode):
        return (
            node.else_body is not None
            and _sequence_always_transfers(node.then_body)
            and _sequence_always_transfers(node.else_body)
        )
    return False


def _sequence_always_transfers(nodes: Sequence[Node]) -> bool:
    return bool(nodes) and _node_always_transfers(nodes[-1])


def _prune_unreachable(nodes: Sequence[Node]) -> List[Node]:
    result: List[Node] = []
    for node in nodes:
        result.append(node)
        if _node_always_transfers(node):
            break
    return result


def _find_matching_brace(lines: Sequence[str], open_index: int, end: int) -> int:
    depth = 0
    for index in range(open_index, end):
        # Hex-Rays braces occur outside strings in ordinary pseudocode.  Count
        # only standalone/control braces to avoid format-string braces.
        stripped = lines[index].strip()
        if stripped == "{":
            depth += 1
        elif stripped == "}":
            depth -= 1
            if depth == 0:
                return index
    raise ValueError("unbalanced pseudocode braces at line %d" % (open_index + 1))


def _condition_from_header(line: str) -> Optional[str]:
    stripped = line.strip()
    if not stripped.startswith("if"):
        return None
    match = re.match(r"if\s*\((.*)\)\s*$", stripped)
    return match.group(1).strip() if match else None


def _parse_controlled_body(
    lines: Sequence[str], index: int, end: int, parent_indent: int
) -> Tuple[List[Node], int]:
    if index >= end:
        return [], index
    if lines[index].strip() == "{":
        close = _find_matching_brace(lines, index, end)
        body = parse_sequence(lines, index + 1, close, parent_indent + 2)
        return body, close + 1
    # Unbraced body: IDA indents it one level.  Parse exactly one logical node.
    body_indent = _indent_of(lines[index])
    nodes = parse_sequence(lines, index, min(end, index + 1), body_indent)
    return nodes, index + 1


def parse_sequence(
    lines: Sequence[str], start: int, end: int, base_indent: int
) -> List[Node]:
    nodes: List[Node] = []
    index = start
    while index < end:
        line = lines[index]
        stripped = line.strip()
        if not stripped:
            nodes.append(RawNode([""]))
            index += 1
            continue
        condition = _condition_from_header(line) if _indent_of(line) == base_indent else None
        if condition is not None:
            then_body, next_index = _parse_controlled_body(lines, index + 1, end, base_indent)
            else_body: Optional[List[Node]] = None
            if next_index < end and _indent_of(lines[next_index]) == base_indent:
                else_line = lines[next_index].strip()
                if else_line == "else":
                    else_body, next_index = _parse_controlled_body(
                        lines, next_index + 1, end, base_indent
                    )
                elif else_line.startswith("else if"):
                    synthetic = " " * base_indent + else_line[5:].lstrip()
                    temp_lines = list(lines)
                    temp_lines[next_index] = synthetic
                    else_nodes = parse_sequence(temp_lines, next_index, end, base_indent)
                    else_body = else_nodes[:1]
                    # This form is rare in Hex-Rays output; consume the rest of
                    # the current sequence conservatively.
                    next_index = end
            nodes.append(IfNode(condition, then_body, else_body))
            index = next_index
            continue

        # Preserve other compound constructs (loops, pre-existing switches,
        # anonymous scopes) verbatim as one raw node.
        if index + 1 < end and lines[index + 1].strip() == "{":
            close = _find_matching_brace(lines, index + 1, end)
            raw = [_strip_base(item, base_indent) for item in lines[index:close + 1]]
            nodes.append(RawNode(raw))
            index = close + 1
            continue
        raw_line = _strip_base(line, base_indent)
        label_match = re.fullmatch(r"([A-Za-z_]\w*):", raw_line.strip())
        if label_match:
            nodes.append(LabelNode(label_match.group(1)))
        else:
            nodes.append(RawNode([raw_line]))
        index += 1
    return nodes


def _walk_if_nodes(nodes: Sequence[Node]) -> Iterable[IfNode]:
    for node in nodes:
        if isinstance(node, IfNode):
            yield node
            yield from _walk_if_nodes(node.then_body)
            if node.else_body is not None:
                yield from _walk_if_nodes(node.else_body)


def _condition_values(node: IfNode, variable: str) -> Set[int]:
    result: Set[int] = set()
    for item in _walk_if_nodes([node]):
        parsed = parse_simple_condition(item.condition)
        if parsed and parsed[0] == variable:
            result.add(parsed[2])
    return result


def _command_equality_values(
    node: IfNode, variable: str, command_values: Set[int]
) -> Set[int]:
    result: Set[int] = set()
    for item in _walk_if_nodes([node]):
        parsed = parse_simple_condition(item.condition)
        if (
            parsed
            and parsed[0] == variable
            and parsed[1] in ("==", "!=")
            and parsed[2] in command_values
        ):
            result.add(parsed[2])
    return result


def _node_weight(node: IfNode) -> int:
    return sum(1 for _ in _walk_if_nodes([node]))


def infer_dispatch_variable(text: str, command_values: Set[int]) -> Optional[str]:
    counts: Counter[str] = Counter()
    for line in text.splitlines():
        condition = _condition_from_header(line)
        if condition is None:
            continue
        parsed = parse_simple_condition(condition)
        if parsed and parsed[2] in command_values and parsed[1] in ("==", "!="):
            counts[parsed[0]] += 1
    return counts.most_common(1)[0][0] if counts else None


def find_dispatch_root(
    nodes: Sequence[Node], variable: str, command_values: Set[int]
) -> Optional[IfNode]:
    candidates = []
    for node in _walk_if_nodes(nodes):
        values = _condition_values(node, variable)
        if command_values.issubset(values):
            candidates.append(node)
    return min(candidates, key=_node_weight) if candidates else None


def _first_following_label_index(nodes: Sequence[Node], start: int) -> int:
    for index in range(start, len(nodes)):
        if isinstance(nodes[index], LabelNode):
            return index
    return len(nodes)


def _region_weight(region: DispatchRegion) -> int:
    return len(render_nodes(region.nodes, 0))


def find_dispatch_region(
    nodes: List[Node], variable: str, command_values: Set[int]
) -> Optional[DispatchRegion]:
    """Find the smallest structured sequence covering all command tests.

    Compilers emit both nested if-ladders and sequential guarded regions.  A
    sequential form typically handles one command in an early if, falls
    through to another command test, and leaves the final command body after
    the last comparison.  The region therefore ends at the next top-level
    label (usually the shared function epilogue), not at the last if node.
    """
    candidates: List[DispatchRegion] = []

    direct: List[Tuple[int, Set[int]]] = []
    for index, node in enumerate(nodes):
        if isinstance(node, IfNode):
            values = _command_equality_values(node, variable, command_values)
            if values:
                direct.append((index, values))
    for left in range(len(direct)):
        covered: Set[int] = set()
        for right in range(left, len(direct)):
            covered.update(direct[right][1])
            if command_values.issubset(covered):
                start_index = direct[left][0]
                last_condition_index = direct[right][0]
                end_index = _first_following_label_index(nodes, last_condition_index + 1)
                if end_index <= last_condition_index:
                    end_index = last_condition_index + 1
                candidates.append(DispatchRegion(nodes, start_index, end_index))
                break

    for node in nodes:
        if isinstance(node, IfNode):
            nested = find_dispatch_region(node.then_body, variable, command_values)
            if nested:
                candidates.append(nested)
            if node.else_body is not None:
                nested = find_dispatch_region(node.else_body, variable, command_values)
                if nested:
                    candidates.append(nested)
    return min(candidates, key=_region_weight) if candidates else None


def _same_nodes(left: Sequence[Node], right: Sequence[Node]) -> bool:
    return render_nodes(left, 0) == render_nodes(right, 0)


def specialize_nodes(nodes: Sequence[Node], variable: str, value: int) -> List[Node]:
    result: List[Node] = []
    for node in nodes:
        if not isinstance(node, IfNode):
            result.append(copy.deepcopy(node))
            continue
        decision = eval_simple_condition(node.condition, variable, value)
        if decision is True:
            result.extend(specialize_nodes(node.then_body, variable, value))
        elif decision is False:
            result.extend(specialize_nodes(node.else_body or [], variable, value))
        else:
            then_body = specialize_nodes(node.then_body, variable, value)
            else_body = (
                specialize_nodes(node.else_body, variable, value)
                if node.else_body is not None else None
            )
            if else_body is not None and _same_nodes(then_body, else_body):
                result.extend(then_body)
            else:
                result.append(IfNode(node.condition, then_body, else_body))
    return _prune_unreachable(result)


def specialize_default(
    nodes: Sequence[Node], variable: str, known_values: Set[int]
) -> List[Node]:
    result: List[Node] = []
    for node in nodes:
        if not isinstance(node, IfNode):
            result.append(copy.deepcopy(node))
            continue
        parsed = parse_simple_condition(node.condition)
        decision: Optional[bool] = None
        if parsed and parsed[0] == variable and parsed[2] in known_values:
            if parsed[1] == "==":
                decision = False
            elif parsed[1] == "!=":
                decision = True
        if decision is True:
            result.extend(specialize_default(node.then_body, variable, known_values))
        elif decision is False:
            result.extend(specialize_default(node.else_body or [], variable, known_values))
        else:
            then_body = specialize_default(node.then_body, variable, known_values)
            else_body = (
                specialize_default(node.else_body, variable, known_values)
                if node.else_body is not None else None
            )
            if else_body is not None and _same_nodes(then_body, else_body):
                result.extend(then_body)
            else:
                result.append(IfNode(node.condition, then_body, else_body))
    return _prune_unreachable(result)


def extract_shared_label_sections(
    nodes: Sequence[Node], sections: List[List[Node]]
) -> List[Node]:
    """Hoist label tails out of command cases while preserving gotos.

    Hex-Rays often places shared error tails lexically inside one side of an
    if-ladder.  After case specialization that would either duplicate the tail
    or put its label in an unrelated case.  Replace the fall-through position
    with an explicit goto and emit the labelled tail once after the switch.
    """
    result: List[Node] = []
    index = 0
    while index < len(nodes):
        node = nodes[index]
        if isinstance(node, LabelNode):
            nested_sections: List[List[Node]] = []
            tail = extract_shared_label_sections(nodes[index + 1:], nested_sections)
            sections.append([copy.deepcopy(node)] + tail)
            sections.extend(nested_sections)
            result.append(RawNode(["goto %s;" % node.name]))
            return result
        if isinstance(node, IfNode):
            then_body = extract_shared_label_sections(node.then_body, sections)
            else_body = (
                extract_shared_label_sections(node.else_body, sections)
                if node.else_body is not None else None
            )
            result.append(IfNode(node.condition, then_body, else_body))
        else:
            result.append(copy.deepcopy(node))
        index += 1
    return result


def find_following_label(nodes: Sequence[Node], target: Node) -> Optional[str]:
    for index, node in enumerate(nodes):
        if node is target:
            for following in nodes[index + 1:]:
                if isinstance(following, LabelNode):
                    return following.name
            return None
        if isinstance(node, IfNode):
            found = find_following_label(node.then_body, target)
            if found:
                return found
            if node.else_body is not None:
                found = find_following_label(node.else_body, target)
                if found:
                    return found
    return None


def _replace_node(
    nodes: Sequence[Node], target: IfNode, replacement: Node
) -> Tuple[List[Node], bool]:
    result: List[Node] = []
    replaced = False
    for node in nodes:
        if node is target:
            result.append(replacement)
            replaced = True
            continue
        if isinstance(node, IfNode):
            then_body, then_replaced = _replace_node(node.then_body, target, replacement)
            else_body = node.else_body
            else_replaced = False
            if else_body is not None:
                else_body, else_replaced = _replace_node(else_body, target, replacement)
            result.append(IfNode(node.condition, then_body, else_body))
            replaced = replaced or then_replaced or else_replaced
        else:
            result.append(copy.deepcopy(node))
    return result, replaced


def _replace_region(
    nodes: List[Node], region: DispatchRegion, replacement: Node
) -> Tuple[List[Node], bool]:
    if nodes is region.container:
        return (
            [copy.deepcopy(node) for node in nodes[:region.start]]
            + [replacement]
            + [copy.deepcopy(node) for node in nodes[region.end:]],
            True,
        )
    result: List[Node] = []
    replaced = False
    for node in nodes:
        if isinstance(node, IfNode):
            then_body, then_replaced = _replace_region(node.then_body, region, replacement)
            else_body = node.else_body
            else_replaced = False
            if else_body is not None:
                else_body, else_replaced = _replace_region(else_body, region, replacement)
            result.append(IfNode(node.condition, then_body, else_body))
            replaced = replaced or then_replaced or else_replaced
        else:
            result.append(copy.deepcopy(node))
    return result, replaced


def _semantic_lines(text: str, variable: str) -> Counter[str]:
    result: Counter[str] = Counter()
    for line in text.splitlines():
        normalized = _norm_line(line)
        if not normalized or normalized in ("{", "}", "else"):
            continue
        if normalized.startswith(("/*", "*", "//", "case ", "default:", "switch (")):
            continue
        if normalized == "break;":
            continue
        condition = _condition_from_header(normalized)
        parsed = parse_simple_condition(condition) if condition is not None else None
        if parsed and parsed[0] == variable:
            continue
        result[normalized] += 1
    return result


def rewrite_to_switch(
    pseudocode: str, commands: Sequence[Dict[str, Any]]
) -> Dict[str, Any]:
    values = {int(command["command"]) for command in commands}
    variable = infer_dispatch_variable(pseudocode, values)
    if not variable:
        return {"success": False, "error": "dispatcher variable not found"}

    lines = pseudocode.splitlines()
    try:
        open_index = next(index for index, line in enumerate(lines) if line.strip() == "{")
        close_index = len(lines) - 1 - next(
            index for index, line in enumerate(reversed(lines)) if line.strip() == "}"
        )
    except StopIteration:
        return {"success": False, "error": "function braces not found"}
    if close_index <= open_index:
        return {"success": False, "error": "invalid function brace range"}

    body_indent = 2
    for line in lines[open_index + 1:close_index]:
        if line.strip():
            body_indent = _indent_of(line)
            break
    body = parse_sequence(lines, open_index + 1, close_index, body_indent)
    region = find_dispatch_region(body, variable, values)
    if region is None:
        return {"success": False, "error": "if-ladder/region covering all commands not found"}

    shared_sections: List[List[Node]] = []
    if len(region.nodes) == 1:
        # Nested ladders often put shared error labels lexically inside one
        # command arm.  Hoisting produces a clean switch with one definition.
        clean_region = extract_shared_label_sections(region.nodes, shared_sections)
    else:
        # Sequential dispatch regions already place labels so that later
        # command arms can jump across them.  Keeping that exact layout avoids
        # cutting complex mid-sequence label tails.
        clean_region = [copy.deepcopy(node) for node in region.nodes]
    if not clean_region:
        return {"success": False, "error": "dispatcher label extraction produced empty region"}

    cases = []
    for command in sorted(commands, key=lambda item: int(item["command"])):
        value = int(command["command"])
        cases.append(
            SwitchCase(value, str(command.get("action", "COMMAND")), specialize_nodes(clean_region, variable, value))
        )
    default_body = specialize_default(clean_region, variable, values)
    continuation = None
    for node in region.container[region.end:]:
        if isinstance(node, LabelNode):
            continuation = node.name
            break
    synthetic = continuation is None
    if continuation is None:
        continuation = "KCTF_AFTER_SWITCH"
    switch_node = SwitchNode(
        variable, cases, default_body, shared_sections, continuation, synthetic
    )
    rewritten_body, replaced = _replace_region(body, region, switch_node)
    if not replaced:
        return {"success": False, "error": "dispatcher replacement failed"}

    banner = [
        "/*",
        " * KCTF-FLOW switch-oriented view.",
        " * Generated deterministically from Hex-Rays pseudocode; no statements",
        " * outside command-only predicates are intentionally removed.",
        " */",
    ]
    rewritten_lines = banner + lines[:open_index + 1]
    rewritten_lines.extend(render_nodes(rewritten_body, body_indent))
    rewritten_lines.extend(lines[close_index:])
    rewritten = "\n".join(rewritten_lines) + "\n"

    original_semantics = _semantic_lines(pseudocode, variable)
    rewritten_semantics = _semantic_lines(rewritten, variable)
    missing_unique = sorted(set(original_semantics) - set(rewritten_semantics))
    missing_counter = original_semantics - rewritten_semantics
    occurrence_shortfall = [
        {"line": line, "count": count}
        for line, count in sorted(missing_counter.items())
        if line not in missing_unique
    ]
    original_occurrences = sum(original_semantics.values())
    missing_occurrences = sum(missing_counter.values())
    occurrence_coverage = 1.0 if not original_occurrences else (
        (original_occurrences - missing_occurrences) / original_occurrences
    )
    coverage = 1.0 if not original_semantics else (
        (len(original_semantics) - len(missing_unique)) / len(original_semantics)
    )
    return {
        "success": True,
        "variable": variable,
        "command_values": sorted(values),
        "rewritten": rewritten,
        "source_pseudocode_sha256": hashlib.sha256(pseudocode.encode("utf-8")).hexdigest(),
        "switch_view_sha256": hashlib.sha256(rewritten.encode("utf-8")).hexdigest(),
        "detail_validation": {
            "original_unique_semantic_lines": len(original_semantics),
            "preserved_unique_semantic_lines": len(original_semantics) - len(missing_unique),
            "original_semantic_line_occurrences": original_occurrences,
            "preserved_semantic_line_occurrences": original_occurrences - missing_occurrences,
            "coverage": coverage,
            "occurrence_coverage": occurrence_coverage,
            "missing_lines": missing_unique,
            "deduplicated_occurrences": occurrence_shortfall,
        },
    }


__all__ = [
    "eval_simple_condition",
    "infer_dispatch_variable",
    "parse_simple_condition",
    "rewrite_to_switch",
]
