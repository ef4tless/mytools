#!/usr/bin/env python3
"""Deterministic control-flow summarizer for Linux kernel CTF modules.

Run inside IDA 9.x / IDAPython.  The script deliberately has no network or
LLM dependency.  It combines three sources of evidence:

* the native CFG (always available),
* Hex-Rays ctree if/switch nodes (when the decompiler is available), and
* deterministic kernel-API/string/immediate classification.

The result is a JSON report, a Markdown report, per-function pseudocode, and
Graphviz DOT files.  With --annotate, concise comments are also written back
to the IDB.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import traceback
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from kctf_switch_rewriter import rewrite_to_switch

import ida_auto
import ida_bytes
import ida_funcs
import ida_gdl
import ida_hexrays
import ida_ida
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_lines
import ida_name
import ida_nalt
import ida_pro
import ida_ua
import idautils
import idc


VERSION = "0.3.2"
BADADDR = ida_idaapi.BADADDR


# A small, auditable ruleset works better here than guessing semantics from
# function names with a language model.  The first matching category wins only
# for display ordering; a call may legitimately appear in several categories.
API_RULES: Dict[str, Tuple[str, ...]] = {
    "USER_IN": (
        "copy_from_user", "get_user", "strncpy_from_user",
        "memdup_user", "vmemdup_user", "simple_write_to_buffer",
    ),
    "USER_OUT": (
        "copy_to_user", "put_user", "clear_user",
        "simple_read_from_buffer",
    ),
    "ALLOC": (
        "kmalloc", "kzalloc", "kcalloc", "krealloc", "kmem_cache_alloc",
        "vmalloc", "vzalloc", "alloc_pages", "__get_free_pages",
    ),
    "FREE": (
        "kfree", "kvfree", "vfree", "kmem_cache_free", "free_pages",
        "put_page",
    ),
    "LOCK": (
        "mutex_lock", "mutex_unlock", "spin_lock", "spin_unlock",
        "raw_spin", "down_read", "up_read", "down_write", "up_write",
        "rcu_read_lock", "rcu_read_unlock",
    ),
    "REFCOUNT": (
        "refcount_", "kref_", "atomic_inc", "atomic_dec", "get_task",
        "put_task", "get_file", "fput",
    ),
    "COPY_MEM": (
        "memcpy", "memmove", "memset", "strcpy", "strncpy", "strscpy",
        "sprintf", "snprintf", "vsnprintf",
    ),
    "CHECK": (
        "access_ok", "capable", "security_", "check_", "validate",
        "fortify", "array_index_nospec",
    ),
    "LOG": (
        "printk", "_printk", "pr_info", "pr_err", "pr_warn", "warn_",
        "panic", "bug",
    ),
    "DEVICE": (
        "register_chrdev", "unregister_chrdev", "device_create",
        "device_destroy", "class_create", "class_destroy", "proc_create",
        "debugfs_create", "misc_register", "misc_deregister",
    ),
}

HANDLER_TOKENS: Dict[str, float] = {
    "ioctl": 26.0,
    "unlocked_ioctl": 28.0,
    "compat_ioctl": 25.0,
    "write": 12.0,
    "read": 12.0,
    "open": 7.0,
    "release": 6.0,
    "mmap": 15.0,
    "show": 5.0,
    "store": 8.0,
    "syscall": 10.0,
    "module_init": 5.0,
    "init_module": 5.0,
}


def log(message: str) -> None:
    ida_kernwin.msg("[KCTF-FLOW] %s\n" % message)


def decolor_text(value: Any) -> str:
    """Remove IDA color tags without changing whitespace."""
    try:
        text = ida_lines.tag_remove(str(value))
    except Exception:
        text = str(value)
    try:
        text = ida_pro.str2user(text)
    except Exception:
        pass
    return text


def clean_text(value: Any) -> str:
    """Remove IDA color tags and keep generated tables one-line."""
    text = decolor_text(value)
    return re.sub(r"\s+", " ", text).strip()


def hex_ea(ea: int) -> str:
    return "0x%x" % int(ea)


def safe_name(ea: int) -> str:
    name = ida_name.get_name(ea)
    if not name:
        name = ida_funcs.get_func_name(ea)
    return clean_text(name or hex_ea(ea))


def safe_filename(name: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("._")
    return value[:120] or "function"


def uniq(values: Iterable[Any]) -> List[Any]:
    seen: Set[Any] = set()
    result: List[Any] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def string_at(ea: int) -> Optional[str]:
    try:
        raw = ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C)
        if raw is None:
            raw = idc.get_strlit_contents(ea, -1, idc.STRTYPE_C)
        if raw is None:
            return None
        if isinstance(raw, bytes):
            return raw.decode("utf-8", "replace")
        return str(raw)
    except Exception:
        return None


def categories_for_call(name: str) -> List[str]:
    lowered = name.lower()
    categories = []
    for category, needles in API_RULES.items():
        if any(needle in lowered for needle in needles):
            categories.append(category)
    return categories


def summarize_calls(calls: Iterable[str]) -> Dict[str, List[str]]:
    summary: Dict[str, List[str]] = defaultdict(list)
    for call in sorted(set(calls)):
        for category in categories_for_call(call):
            summary[category].append(call)
    return dict(sorted(summary.items()))


def decode_ioctl(value: int) -> Dict[str, Any]:
    """Decode the common Linux generic _IOC layout.

    Architecture-specific overrides exist, so this is explicitly labelled as
    a generic decode in the output.  It is still very useful for CTF handlers.
    """
    value &= 0xFFFFFFFF
    direction = (value >> 30) & 0x3
    size = (value >> 16) & 0x3FFF
    type_value = (value >> 8) & 0xFF
    nr = value & 0xFF
    direction_names = {0: "NONE", 1: "WRITE", 2: "READ", 3: "READ|WRITE"}
    type_display = chr(type_value) if 0x20 <= type_value <= 0x7E else None
    return {
        "raw": "0x%08x" % value,
        "direction": direction_names[direction],
        "type": type_value,
        "type_ascii": type_display,
        "number": nr,
        "size": size,
    }


def decode_fourcc(value: int) -> Optional[str]:
    raw = int(value & 0xFFFFFFFF).to_bytes(4, "little")
    if all(0x20 <= byte <= 0x7E for byte in raw):
        return raw.decode("ascii")
    return None


def looks_like_ioctl(value: int) -> bool:
    value &= 0xFFFFFFFF
    # Avoid decoding every large application-specific magic as a generic
    # Linux _IOC value.  A normal _IO command has direction=NONE, size=0 and
    # a printable magic/type byte.  Commands carrying data likewise normally
    # use a printable magic.  Requiring it avoids treating buffer sizes such
    # as 0x100, or values such as 0x20250001, as _IOC encodings.
    direction = (value >> 30) & 0x3
    size = (value >> 16) & 0x3FFF
    type_value = (value >> 8) & 0xFF
    if value <= 0xFF or not 0x20 <= type_value <= 0x7E:
        return False
    if direction == 0:
        return size == 0
    return True


def instruction_text(ea: int) -> str:
    try:
        return clean_text(idc.generate_disasm_line(ea, 0) or "")
    except Exception:
        return ""


def code_heads(start_ea: int, end_ea: int) -> List[int]:
    return [
        ea for ea in idautils.Heads(start_ea, end_ea)
        if ida_bytes.is_code(ida_bytes.get_flags(ea))
    ]


def direct_callee_at(ea: int, current_func_ea: int) -> Optional[str]:
    try:
        if not ida_idp.is_call_insn(ea):
            return None
    except Exception:
        if not idc.print_insn_mnem(ea).lower().startswith("call"):
            return None
    for target in idautils.CodeRefsFrom(ea, False):
        func = ida_funcs.get_func(target)
        target_ea = func.start_ea if func else target
        if target_ea != current_func_ea:
            return safe_name(target_ea)
    # Indirect calls still carry useful operand text.
    operand = clean_text(idc.print_operand(ea, 0) or "")
    return operand or None


def immediates_at(ea: int) -> List[int]:
    result: List[int] = []
    for index in range(ida_ida.UA_MAXOP):
        try:
            if idc.get_operand_type(ea, index) == idc.o_imm:
                result.append(int(idc.get_operand_value(ea, index)))
        except Exception:
            break
    return result


def block_features(start_ea: int, end_ea: int, func_ea: int) -> Dict[str, Any]:
    heads = code_heads(start_ea, end_ea)
    calls: List[str] = []
    strings: List[str] = []
    constants: List[int] = []
    for ea in heads:
        callee = direct_callee_at(ea, func_ea)
        if callee:
            calls.append(callee)
        constants.extend(immediates_at(ea))
        for target in idautils.DataRefsFrom(ea):
            value = string_at(target)
            if value:
                strings.append(value)
    tail = heads[-1] if heads else start_ea
    context = [instruction_text(ea) for ea in heads[-4:]]
    return {
        "instruction_count": len(heads),
        "tail_ea": tail,
        "tail_context": [line for line in context if line],
        "calls": uniq(calls),
        "call_categories": summarize_calls(calls),
        "strings": uniq(strings),
        "constants": uniq(constants),
    }


def compute_postdominators(
    node_ids: Sequence[int], successors: Dict[int, List[int]]
) -> Tuple[Dict[int, Set[int]], Dict[int, Optional[int]]]:
    """Return postdominator sets and immediate postdominators.

    A synthetic exit is used so multiple returns and error exits are handled
    uniformly.  The function intentionally stays pure Python for easy audit.
    """
    if not node_ids:
        return {}, {}
    virtual_exit = max(node_ids) + 1
    universe = set(node_ids) | {virtual_exit}
    succ: Dict[int, List[int]] = {
        node: list(successors.get(node, [])) for node in node_ids
    }
    exits = [node for node in node_ids if not succ[node]]
    if not exits:
        # Degenerate endless loop: attach all nodes to the virtual exit only as
        # a convergence aid.  Reports still expose the actual successor map.
        exits = list(node_ids)
    for node in exits:
        succ[node] = list(succ[node]) + [virtual_exit]
    succ[virtual_exit] = []

    pdom: Dict[int, Set[int]] = {node: set(universe) for node in universe}
    pdom[virtual_exit] = {virtual_exit}
    changed = True
    while changed:
        changed = False
        for node in node_ids:
            children = succ[node]
            if not children:
                new_set = {node, virtual_exit}
            else:
                common = set(pdom[children[0]])
                for child in children[1:]:
                    common.intersection_update(pdom[child])
                new_set = {node} | common
            if new_set != pdom[node]:
                pdom[node] = new_set
                changed = True

    ipdom: Dict[int, Optional[int]] = {}
    for node in node_ids:
        strict = pdom[node] - {node, virtual_exit}
        if not strict:
            ipdom[node] = None
        else:
            # The nearest postdominator has the largest postdominator set.
            ipdom[node] = max(strict, key=lambda candidate: len(pdom[candidate]))
    return pdom, ipdom


def reachable_until(
    start: int, stop: Optional[int], successors: Dict[int, List[int]]
) -> Set[int]:
    pending = [start]
    seen: Set[int] = set()
    while pending:
        node = pending.pop()
        if node in seen or node == stop:
            continue
        seen.add(node)
        pending.extend(successors.get(node, []))
    return seen


def merge_feature_sets(
    block_ids: Iterable[int], blocks_by_id: Dict[int, Dict[str, Any]]
) -> Dict[str, Any]:
    calls: List[str] = []
    strings: List[str] = []
    constants: List[int] = []
    instruction_count = 0
    for block_id in sorted(set(block_ids)):
        block = blocks_by_id[block_id]
        features = block["features"]
        instruction_count += features["instruction_count"]
        calls.extend(features["calls"])
        strings.extend(features["strings"])
        constants.extend(features["constants"])
    return {
        "block_ids": sorted(set(block_ids)),
        "instruction_count": instruction_count,
        "calls": uniq(calls),
        "call_categories": summarize_calls(calls),
        "strings": uniq(strings),
        "constants": uniq(constants),
    }


def parse_ida_integer(text: str) -> Optional[int]:
    value = text.strip().lower().replace("`", "")
    value = re.sub(r"\b(?:byte|word|dword|qword)\s+ptr\b", "", value).strip()
    try:
        if value.endswith("h") and re.fullmatch(r"[0-9a-f]+h", value):
            return int(value[:-1], 16)
        return int(value, 0)
    except ValueError:
        return None


def parse_equality_branch(branch: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Recognize a compiled ``cmp operand, imm`` + JE/JNE dispatcher node."""
    context = branch.get("site_context", [])
    if len(context) < 2:
        return None
    jump_match = re.match(r"\s*(jz|je|jnz|jne)\b", context[-1], re.IGNORECASE)
    if not jump_match:
        return None
    compare_line = None
    for line in reversed(context[:-1]):
        if re.match(r"\s*cmp\b", line, re.IGNORECASE):
            compare_line = line
            break
    if compare_line is None:
        return None
    compare_match = re.match(r"\s*cmp\s+(.+?),\s*([^,;]+)", compare_line, re.IGNORECASE)
    if not compare_match:
        return None
    operand = clean_text(compare_match.group(1)).lower()
    constant = parse_ida_integer(compare_match.group(2))
    if constant is None:
        return None
    jump = jump_match.group(1).lower()
    equality_kind = "taken" if jump in ("jz", "je") else "fallthrough"
    selected_edge = next(
        (edge for edge in branch.get("edges", []) if edge.get("kind") == equality_kind),
        None,
    )
    if selected_edge is None:
        return None
    return {
        "operand": operand,
        "command": constant,
        "jump": jump,
        "selected_edge_kind": equality_kind,
        "selected_edge": selected_edge,
    }


def infer_action(features: Dict[str, Any]) -> str:
    categories = set(features.get("call_categories", {}).keys())
    if "ALLOC" in categories:
        return "CREATE/ALLOC"
    if "FREE" in categories and "USER_OUT" not in categories:
        return "DELETE/FREE"
    if "USER_OUT" in categories:
        return "READ/QUERY"
    if "USER_IN" in categories:
        return "WRITE/UPDATE"
    if "DEVICE" in categories:
        return "DEVICE/CONTROL"
    if "LOCK" in categories:
        return "STATE/LOCKED"
    return "CONTROL"


def classify_guard(context: Sequence[str]) -> List[str]:
    text = " ; ".join(context).lower()
    kinds: List[str] = []
    if ("copy_from_user" in text or "copy_to_user" in text) and "test" in text:
        kinds.append("USER_COPY_RESULT")
    if any(token in text for token in ("kmalloc", "kzalloc", "kmem_cache_alloc", "vmalloc")) and "test" in text:
        kinds.append("ALLOC_RESULT")
    if "__stack_chk" in text or "gs:28h" in text:
        kinds.append("STACK_CANARY")
    if "test" in text and re.search(r"\bj[sn]", text):
        kinds.append("SIGNED_VALUE")
    if re.search(r"\bcmp\b.*\b(?:0?f|10|7ff|800)h?\b", text) and re.search(
        r"\bj(?:a|ae|b|be|g|ge|l|le|nb|na)\b", text
    ):
        kinds.append("BOUNDS")
    if ("cmp" in text or "test" in text) and re.search(r"\bj(?:z|nz|e|ne)\b", text):
        if any(token in text for token in ("qword", "dword", "ptr", "[")):
            kinds.append("STATE_EXISTS")
    if re.search(r"\bcmp\b.*(?:size|len|list)", text) or re.search(
        r"\bcmp\b.*\[.*\]", text
    ):
        kinds.append("LENGTH_OR_STATE")
    return uniq(kinds) or ["CONDITION"]


def recover_dispatch_commands(branches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Recover the dominant equality-dispatch operand and its command regions.

    Kernel CTF handlers are commonly compiled from an if/else-if ladder.  The
    decompiler can flatten it into gotos, but repeated comparisons of the same
    register against distinct immediates survive.  Grouping that register is a
    stable way to reconstruct subcommands without any semantic model.
    """
    parsed: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    for branch in branches:
        item = parse_equality_branch(branch)
        if item:
            parsed.append((branch, item))
    if not parsed:
        return []
    operand_values: Dict[str, Set[int]] = defaultdict(set)
    for _, item in parsed:
        operand_values[item["operand"]].add(item["command"])
    # Prefer many distinct command constants, then total occurrences.  A
    # minimum of two constants prevents ordinary null checks from becoming a
    # fake dispatcher.
    occurrence_count = Counter(item["operand"] for _, item in parsed)
    operand = max(
        operand_values,
        key=lambda name: (len(operand_values[name]), occurrence_count[name]),
    )
    if len(operand_values[operand]) < 2:
        return []

    commands: List[Dict[str, Any]] = []
    for branch, item in parsed:
        if item["operand"] != operand:
            continue
        edge = item["selected_edge"]
        features = edge["features"]
        fourcc = decode_fourcc(item["command"])
        region_blocks = set(features.get("block_ids", []))
        guards = []
        for candidate in branches:
            if candidate["block_id"] in region_blocks and candidate is not branch:
                guards.append({
                    "site_ea": candidate["site_ea"],
                    "context": candidate["site_context"],
                    "kinds": classify_guard(candidate["site_context"]),
                })
        commands.append({
            "operand": operand,
            "command": item["command"],
            "command_hex": "0x%x" % item["command"],
            "site_ea": branch["site_ea"],
            "jump": item["jump"],
            "selected_edge_kind": item["selected_edge_kind"],
            "target_ea": edge["target_ea"],
            "action": infer_action(features),
            "features": features,
            "guards": guards,
            "fourcc_le": fourcc,
            "ioctl": decode_ioctl(item["command"])
            if looks_like_ioctl(item["command"]) and fourcc is None else None,
        })
    commands.sort(key=lambda item: (item["command"], item["site_ea"]))
    return commands


def edge_kind(tail_ea: int, target_start: int) -> str:
    refs = list(idautils.CodeRefsFrom(tail_ea, True))
    next_ea = idc.next_head(tail_ea, BADADDR)
    if target_start == next_ea:
        return "fallthrough"
    if target_start in refs:
        return "taken"
    return "edge"


def build_cfg(func_ea: int) -> Dict[str, Any]:
    func = ida_funcs.get_func(func_ea)
    if not func:
        raise ValueError("No function at %s" % hex_ea(func_ea))
    flow = ida_gdl.FlowChart(func, flags=ida_gdl.FC_PREDS)
    raw_blocks = list(flow)
    blocks_by_id: Dict[int, Dict[str, Any]] = {}
    successors: Dict[int, List[int]] = {}
    predecessors: Dict[int, List[int]] = {}
    for block in raw_blocks:
        succ_ids = [succ.id for succ in block.succs()]
        pred_ids = [pred.id for pred in block.preds()]
        successors[block.id] = succ_ids
        predecessors[block.id] = pred_ids
        blocks_by_id[block.id] = {
            "id": block.id,
            "start_ea": int(block.start_ea),
            "end_ea": int(block.end_ea),
            "successors": succ_ids,
            "predecessors": pred_ids,
            "features": block_features(block.start_ea, block.end_ea, func.start_ea),
        }

    node_ids = sorted(blocks_by_id)
    _, ipdom = compute_postdominators(node_ids, successors)
    branch_records: List[Dict[str, Any]] = []
    for block_id in node_ids:
        block = blocks_by_id[block_id]
        succ_ids = successors[block_id]
        if len(succ_ids) < 2:
            continue
        merge = ipdom.get(block_id)
        edges = []
        tail_ea = block["features"]["tail_ea"]
        for succ_id in succ_ids:
            region = reachable_until(succ_id, merge, successors)
            # Blocks reachable from all alternatives are common tail material,
            # not branch-specific behavior.  Remove them below.
            edges.append({
                "target_block": succ_id,
                "kind": edge_kind(tail_ea, blocks_by_id[succ_id]["start_ea"]),
                "region_blocks": region,
            })
        if len(edges) >= 2:
            common = set.intersection(*(set(edge["region_blocks"]) for edge in edges))
        else:
            common = set()
        for edge in edges:
            unique_region = set(edge.pop("region_blocks")) - common
            edge["target_ea"] = blocks_by_id[edge["target_block"]]["start_ea"]
            edge["features"] = merge_feature_sets(unique_region, blocks_by_id)
        branch_records.append({
            "block_id": block_id,
            "site_ea": tail_ea,
            "site_context": block["features"]["tail_context"],
            "merge_block": merge,
            "merge_ea": blocks_by_id[merge]["start_ea"] if merge is not None else None,
            "edges": edges,
        })

    edge_count = sum(len(values) for values in successors.values())
    block_count = len(node_ids)
    cyclomatic = max(1, edge_count - block_count + 2) if block_count else 0
    all_features = merge_feature_sets(node_ids, blocks_by_id)
    recovered_commands = recover_dispatch_commands(branch_records)
    return {
        "blocks": [blocks_by_id[node] for node in node_ids],
        "block_count": block_count,
        "edge_count": edge_count,
        "branch_count": len(branch_records),
        "cyclomatic_complexity": cyclomatic,
        "calls": all_features["calls"],
        "call_categories": all_features["call_categories"],
        "strings": all_features["strings"],
        "constants": all_features["constants"],
        "branches": branch_records,
        "recovered_commands": recovered_commands,
    }


class CTreeFeatureVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self, cfunc: ida_hexrays.cfunc_t) -> None:
        super().__init__(ida_hexrays.CV_FAST)
        self.cfunc = cfunc
        self.calls: List[str] = []
        self.strings: List[str] = []
        self.constants: List[int] = []
        self.member_offsets: List[int] = []

    def visit_expr(self, expr: ida_hexrays.cexpr_t) -> int:
        try:
            if expr.op == ida_hexrays.cot_call:
                callee_expr = expr.x
                if callee_expr.op == ida_hexrays.cot_obj:
                    name = safe_name(callee_expr.obj_ea)
                else:
                    name = clean_text(callee_expr.print1(self.cfunc))
                if name:
                    self.calls.append(name)
            elif expr.op == ida_hexrays.cot_num:
                self.constants.append(int(expr.numval()))
            elif expr.op == ida_hexrays.cot_obj:
                value = string_at(expr.obj_ea)
                if value:
                    self.strings.append(value)
            elif expr.op in (ida_hexrays.cot_memptr, ida_hexrays.cot_memref):
                self.member_offsets.append(int(expr.m))
        except Exception:
            pass
        return 0

    def result(self) -> Dict[str, Any]:
        return {
            "calls": uniq(self.calls),
            "call_categories": summarize_calls(self.calls),
            "strings": uniq(self.strings),
            "constants": uniq(self.constants),
            "member_offsets": uniq(self.member_offsets),
        }


def ctree_features(
    cfunc: ida_hexrays.cfunc_t, item: Optional[ida_hexrays.citem_t]
) -> Dict[str, Any]:
    if item is None:
        return {
            "calls": [], "call_categories": {}, "strings": [],
            "constants": [], "member_offsets": [],
        }
    visitor = CTreeFeatureVisitor(cfunc)
    visitor.apply_to(item, None)
    return visitor.result()


class CTreeControlVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self, cfunc: ida_hexrays.cfunc_t, annotate: bool) -> None:
        super().__init__(ida_hexrays.CV_PARENTS | ida_hexrays.CV_INSNS)
        self.cfunc = cfunc
        self.annotate = annotate
        self.ifs: List[Dict[str, Any]] = []
        self.switches: List[Dict[str, Any]] = []

    def _depth_and_parents(self) -> Tuple[int, List[int]]:
        parent_eas: List[int] = []
        try:
            for parent in self.parents:
                if parent.op in (ida_hexrays.cit_if, ida_hexrays.cit_switch):
                    parent_eas.append(int(parent.ea))
        except Exception:
            pass
        return len(parent_eas), parent_eas

    def _expr_text(self, expr: ida_hexrays.cexpr_t) -> str:
        try:
            return clean_text(expr.print1(self.cfunc))
        except Exception:
            try:
                return clean_text(expr.dstr())
            except Exception:
                return "<unprintable>"

    def visit_insn(self, insn: ida_hexrays.cinsn_t) -> int:
        depth, parent_eas = self._depth_and_parents()
        if insn.op == ida_hexrays.cit_if:
            condition_features = ctree_features(self.cfunc, insn.cif.expr)
            record = {
                "ea": int(insn.ea),
                "depth": depth,
                "parent_control_eas": parent_eas,
                "condition": self._expr_text(insn.cif.expr),
                "condition_features": condition_features,
                "then": ctree_features(self.cfunc, insn.cif.ithen),
                "else": ctree_features(self.cfunc, insn.cif.ielse),
            }
            self.ifs.append(record)
            if self.annotate and insn.ea != BADADDR:
                comment = "[KCTF] if depth=%d: %s" % (depth, record["condition"])
                ida_bytes.set_cmt(insn.ea, comment[:500], False)
        elif insn.op == ida_hexrays.cit_switch:
            switch = insn.cswitch
            cases: List[Dict[str, Any]] = []
            for case in switch.cases:
                values = [int(value) for value in case.values]
                cases.append({
                    "values": values,
                    "default": not values,
                    "features": ctree_features(self.cfunc, case),
                })
            record = {
                "ea": int(insn.ea),
                "depth": depth,
                "parent_control_eas": parent_eas,
                "expression": self._expr_text(switch.expr),
                "expression_features": ctree_features(self.cfunc, switch.expr),
                "cases": cases,
            }
            self.switches.append(record)
            if self.annotate and insn.ea != BADADDR:
                comment = "[KCTF] switch depth=%d: %s" % (
                    depth, record["expression"]
                )
                ida_bytes.set_cmt(insn.ea, comment[:500], False)
        return 0


def pseudocode_text(cfunc: ida_hexrays.cfunc_t) -> str:
    return "\n".join(decolor_text(line.line).rstrip() for line in cfunc.get_pseudocode())


def decompile_control(func_ea: int, annotate: bool) -> Dict[str, Any]:
    if not ida_hexrays.init_hexrays_plugin():
        return {"available": False, "error": "Hex-Rays is not available"}
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        if not cfunc:
            return {"available": False, "error": "decompile() returned null"}
        visitor = CTreeControlVisitor(cfunc, annotate)
        visitor.apply_to(cfunc.body, None)
        return {
            "available": True,
            "ifs": visitor.ifs,
            "switches": visitor.switches,
            "pseudocode": pseudocode_text(cfunc),
        }
    except Exception as exc:
        return {
            "available": False,
            "error": "%s: %s" % (type(exc).__name__, exc),
        }


def score_profile(name: str, cfg: Dict[str, Any]) -> Tuple[float, List[str]]:
    lowered = name.lower()
    score = 0.0
    reasons: List[str] = []
    for token, weight in HANDLER_TOKENS.items():
        if token in lowered:
            score += weight
            reasons.append("name:%s" % token)
    if lowered.startswith("__cfi_"):
        score -= 30.0
        reasons.append("wrapper:__cfi")
    if lowered.startswith("__pfx_"):
        score -= 100.0
        reasons.append("wrapper:__pfx")
    branches = cfg["branch_count"]
    complexity = cfg["cyclomatic_complexity"]
    if branches:
        branch_score = min(20.0, branches * 1.7)
        score += branch_score
        reasons.append("branches:%d" % branches)
    if complexity > 1:
        score += min(12.0, (complexity - 1) * 0.8)
        reasons.append("complexity:%d" % complexity)
    for category in ("USER_IN", "USER_OUT", "ALLOC", "FREE"):
        if category in cfg["call_categories"]:
            score += 3.5
            reasons.append(category)
    if cfg["strings"]:
        score += min(4.0, len(cfg["strings"]) * 0.5)
        reasons.append("strings:%d" % len(cfg["strings"]))
    return round(score, 2), reasons


def profile_function(func_ea: int) -> Dict[str, Any]:
    func = ida_funcs.get_func(func_ea)
    if not func:
        raise ValueError("No function at %s" % hex_ea(func_ea))
    cfg = build_cfg(func.start_ea)
    name = safe_name(func.start_ea)
    score, reasons = score_profile(name, cfg)
    return {
        "ea": int(func.start_ea),
        "end_ea": int(func.end_ea),
        "name": name,
        "size": int(func.end_ea - func.start_ea),
        "score": score,
        "score_reasons": reasons,
        "cfg": cfg,
    }


def discover_candidates(top: int, min_score: float) -> List[Dict[str, Any]]:
    profiles: List[Dict[str, Any]] = []
    total = ida_funcs.get_func_qty()
    log("profiling %d functions" % total)
    for index, ea in enumerate(idautils.Functions()):
        try:
            profile = profile_function(int(ea))
            if profile["score"] >= min_score:
                profiles.append(profile)
        except Exception as exc:
            log("skip %s: %s" % (hex_ea(int(ea)), exc))
        if index and index % 250 == 0:
            log("profiled %d/%d functions" % (index, total))
    profiles.sort(key=lambda item: (-item["score"], -item["cfg"]["branch_count"], item["ea"]))
    return profiles[:top] if top > 0 else profiles


def resolve_function(selector: str) -> Optional[int]:
    value = selector.strip()
    try:
        ea = int(value, 0)
    except ValueError:
        ea = ida_name.get_name_ea(BADADDR, value)
    if ea == BADADDR:
        return None
    func = ida_funcs.get_func(ea)
    return int(func.start_ea) if func else None


def render_feature_cell(features: Dict[str, Any], limit: int = 4) -> str:
    pieces: List[str] = []
    categories = list(features.get("call_categories", {}).keys())
    if categories:
        pieces.append("/".join(categories))
    calls = features.get("calls", [])
    if calls:
        pieces.append("calls=" + ", ".join(calls[:limit]))
    strings = features.get("strings", [])
    if strings:
        pieces.append("str=" + ", ".join(repr(value[:60]) for value in strings[:2]))
    offsets = features.get("member_offsets", [])
    if offsets:
        pieces.append("fields=" + ",".join("0x%x" % value for value in offsets[:8]))
    return "; ".join(pieces) or "-"


def md_escape(value: Any) -> str:
    return clean_text(value).replace("|", "\\|").replace("`", "'")


def ioctl_cells(constants: Iterable[int]) -> str:
    decoded = []
    for value in constants:
        if looks_like_ioctl(int(value)) and decode_fourcc(int(value)) is None:
            item = decode_ioctl(int(value))
            type_part = (
                "'%s'" % item["type_ascii"]
                if item["type_ascii"] is not None
                else "0x%02x" % item["type"]
            )
            decoded.append(
                "%s dir=%s type=%s nr=%d size=%d" % (
                    item["raw"], item["direction"], type_part,
                    item["number"], item["size"],
                )
            )
    return "; ".join(decoded)


def render_markdown(report: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("# Kernel CTF control-flow report")
    lines.append("")
    lines.append("- Input: `%s`" % report["input_path"])
    lines.append("- IDA input SHA-256: `%s`" % report.get("input_sha256", "unknown"))
    lines.append("- Script version: `%s`" % report["script_version"])
    lines.append("- Generated: `%s`" % report["generated_at"])
    lines.append("- Model/network dependency: **none**")
    lines.append("")
    lines.append("## Candidate ranking")
    lines.append("")
    lines.append("| Score | Function | EA | Branches | Cyclomatic | Reasons |")
    lines.append("|---:|---|---:|---:|---:|---|")
    for candidate in report["candidate_ranking"]:
        cfg = candidate["cfg"]
        lines.append(
            "| %.2f | `%s` | `%s` | %d | %d | %s |" % (
                candidate["score"], md_escape(candidate["name"]),
                hex_ea(candidate["ea"]), cfg["branch_count"],
                cfg["cyclomatic_complexity"],
                md_escape(", ".join(candidate["score_reasons"])),
            )
        )

    for function in report["functions"]:
        cfg = function["cfg"]
        ctree = function["ctree"]
        lines.extend([
            "",
            "## `%s` at `%s`" % (md_escape(function["name"]), hex_ea(function["ea"])),
            "",
            "- Size: `%d` bytes" % function["size"],
            "- CFG: `%d` blocks, `%d` edges, `%d` branch sites, cyclomatic `%d`" % (
                cfg["block_count"], cfg["edge_count"], cfg["branch_count"],
                cfg["cyclomatic_complexity"],
            ),
            "- Kernel API classes: `%s`" % (
                ", ".join(cfg["call_categories"].keys()) or "none"
            ),
            "- Hex-Rays: `%s`" % ("available" if ctree.get("available") else ctree.get("error", "unavailable")),
        ])
        switch_view = function.get("switch_view", {})
        if switch_view.get("success"):
            validation = switch_view["detail_validation"]
            lines.append(
                "- Switch view: `%s`, semantic-detail coverage `%.2f%%` (unique %d/%d; occurrences %d/%d)" % (
                    switch_view["relative_path"],
                    validation["coverage"] * 100.0,
                    validation["preserved_unique_semantic_lines"],
                    validation["original_unique_semantic_lines"],
                    validation["preserved_semantic_line_occurrences"],
                    validation["original_semantic_line_occurrences"],
                )
            )

        commands = cfg.get("recovered_commands", [])
        if commands:
            lines.extend([
                "",
                "### Recovered command subfunctions",
                "",
                "Repeated equality comparisons of `%s` identify the dispatcher." % md_escape(commands[0]["operand"]),
                "",
                "| Command | Compare site | Equality edge | Deterministic action | Region evidence | Guards |",
                "|---:|---:|---|---|---|---:|",
            ])
            for command in commands:
                command_display = command["command_hex"]
                if command.get("fourcc_le"):
                    command_display += " ('%s')" % command["fourcc_le"]
                lines.append(
                    "| `%s` (%d) | `%s` | %s -> `%s` | **%s** | %s | %d |" % (
                        command_display, command["command"],
                        hex_ea(command["site_ea"]), command["selected_edge_kind"],
                        hex_ea(command["target_ea"]), command["action"],
                        md_escape(render_feature_cell(command["features"])),
                        len(command["guards"]),
                    )
                )
            for command in commands:
                lines.extend([
                    "",
                    "#### Command `%s` — %s" % (command["command_hex"], command["action"]),
                    "",
                    "- Dispatcher: `%s` at `%s`; equality follows `%s` to `%s`." % (
                        command["jump"], hex_ea(command["site_ea"]),
                        command["selected_edge_kind"], hex_ea(command["target_ea"]),
                    ),
                    "- Calls: `%s`" % (", ".join(command["features"].get("calls", [])) or "none"),
                    "- Region blocks: `%s`" % (
                        ", ".join("B%d" % block for block in command["features"].get("block_ids", []))
                        or "none"
                    ),
                ])
                if command["ioctl"]:
                    lines.append("- `_IOC`: `%s`" % md_escape(ioctl_cells([command["command"]])))
                if command["guards"]:
                    lines.append("- Internal guards:")
                    for guard in command["guards"]:
                        lines.append(
                            "  - `%s` **%s**: `%s`" % (
                                hex_ea(guard["site_ea"]),
                                "/".join(guard["kinds"]),
                                md_escape(" ; ".join(guard["context"])),
                            )
                        )

        if ctree.get("available"):
            lines.extend(["", "### Deterministic if tree", ""])
            if not ctree["ifs"]:
                lines.append("No ctree `if` nodes.")
            for index, item in enumerate(ctree["ifs"], 1):
                indent = "  " * item["depth"]
                constants = item["condition_features"].get("constants", [])
                const_text = ", ".join("0x%x" % value for value in constants)
                lines.append(
                    "%s- IF%02d `%s` at `%s`%s" % (
                        indent, index, md_escape(item["condition"]),
                        hex_ea(item["ea"]),
                        " constants=" + const_text if const_text else "",
                    )
                )
                lines.append(
                    "%s  - T: %s" % (
                        indent, md_escape(render_feature_cell(item["then"]))
                    )
                )
                lines.append(
                    "%s  - F: %s" % (
                        indent, md_escape(render_feature_cell(item["else"]))
                    )
                )
                decoded = ioctl_cells(constants)
                if decoded:
                    lines.append("%s  - `_IOC`: %s" % (indent, md_escape(decoded)))

            if ctree["switches"]:
                lines.extend(["", "### Switch dispatchers", ""])
                for index, switch in enumerate(ctree["switches"], 1):
                    lines.append(
                        "- SW%02d `%s` at `%s`" % (
                            index, md_escape(switch["expression"]), hex_ea(switch["ea"])
                        )
                    )
                    for case in switch["cases"]:
                        label = "default" if case["default"] else ", ".join(
                            "0x%x" % value for value in case["values"]
                        )
                        lines.append(
                            "  - `%s`: %s" % (
                                label, md_escape(render_feature_cell(case["features"]))
                            )
                        )
                        decoded = ioctl_cells(case["values"])
                        if decoded:
                            lines.append("    - `_IOC`: %s" % md_escape(decoded))

        lines.extend(["", "### Assembly CFG branch regions", ""])
        lines.append("| Site | Context | Join | Edge | Unique-region behavior |")
        lines.append("|---:|---|---:|---|---|")
        for branch in cfg["branches"]:
            context = " ; ".join(branch["site_context"])
            join = hex_ea(branch["merge_ea"]) if branch["merge_ea"] is not None else "exit"
            for edge in branch["edges"]:
                lines.append(
                    "| `%s` | `%s` | `%s` | %s -> `%s` | %s |" % (
                        hex_ea(branch["site_ea"]), md_escape(context), join,
                        edge["kind"], hex_ea(edge["target_ea"]),
                        md_escape(render_feature_cell(edge["features"])),
                    )
                )
        if cfg["strings"]:
            lines.extend(["", "### Referenced strings", ""])
            for value in cfg["strings"]:
                lines.append("- `%s`" % md_escape(repr(value)))
    lines.append("")
    return "\n".join(lines)


def render_dot(function: Dict[str, Any]) -> str:
    cfg = function["cfg"]
    branch_sites = {branch["block_id"]: branch for branch in cfg["branches"]}
    lines = [
        "digraph kctf_flow {",
        "  rankdir=TB;",
        "  node [shape=box,fontname=\"Menlo\",fontsize=10];",
    ]
    for block in cfg["blocks"]:
        label_parts = [
            "B%d %s" % (block["id"], hex_ea(block["start_ea"])),
        ]
        label_parts.extend(block["features"]["tail_context"][-2:])
        categories = list(block["features"]["call_categories"].keys())
        if categories:
            label_parts.append("[" + "/".join(categories) + "]")
        escaped_parts = [
            part.replace("\\", "\\\\").replace('"', '\\"')
            for part in label_parts
        ]
        label = "\\l".join(escaped_parts)
        attrs = ",style=filled,fillcolor=\"#fff2cc\"" if block["id"] in branch_sites else ""
        lines.append('  B%d [label="%s\\l"%s];' % (block["id"], label, attrs))
    edge_labels: Dict[Tuple[int, int], str] = {}
    for branch in cfg["branches"]:
        for edge in branch["edges"]:
            edge_labels[(branch["block_id"], edge["target_block"])] = edge["kind"]
    for block in cfg["blocks"]:
        for target in block["successors"]:
            label = edge_labels.get((block["id"], target), "")
            suffix = ' [label="%s"]' % label if label else ""
            lines.append("  B%d -> B%d%s;" % (block["id"], target, suffix))
    lines.append("}")
    return "\n".join(lines) + "\n"


def input_sha256(path: str) -> str:
    import hashlib
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except Exception:
        return "unknown"


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ida_kernel_ctf_flow.py",
        description="Deterministic Linux kernel CTF control-flow summarizer",
    )
    parser.add_argument(
        "--func", action="append", default=[], metavar="NAME_OR_EA",
        help="analyze this function; repeatable",
    )
    parser.add_argument(
        "--discover", action="store_true",
        help="analyze ranked handler candidates instead of only the current function",
    )
    parser.add_argument("--top", type=int, default=12, help="candidate limit")
    parser.add_argument("--min-score", type=float, default=6.0)
    parser.add_argument("--out", help="output directory")
    parser.add_argument("--annotate", action="store_true", help="write IDA comments")
    parser.add_argument(
        "--label-commands", action="store_true",
        help="name dispatcher targets as kctf_cmd_<value>_<action>",
    )
    parser.add_argument("--no-hexrays", action="store_true")
    parser.add_argument(
        "--no-switch-view", action="store_true",
        help="do not generate the full-detail switch-oriented pseudocode view",
    )
    parser.add_argument("--save-idb", action="store_true")
    parser.add_argument("--batch", action="store_true", help="exit IDA when finished")
    return parser.parse_args(list(argv))


def choose_targets(
    args: argparse.Namespace, ranking: List[Dict[str, Any]]
) -> List[int]:
    selected: List[int] = []
    for selector in args.func:
        ea = resolve_function(selector)
        if ea is None:
            raise ValueError("function not found: %s" % selector)
        selected.append(ea)
    if selected:
        return uniq(selected)
    if args.discover:
        return [item["ea"] for item in ranking]
    current = ida_funcs.get_func(ida_kernwin.get_screen_ea())
    if current:
        return [int(current.start_ea)]
    if ranking:
        return [ranking[0]["ea"]]
    return []


def execute(args: argparse.Namespace) -> Dict[str, Any]:
    ida_auto.auto_wait()
    input_path = ida_nalt.get_input_file_path()
    default_out = Path(input_path).with_suffix("").name + "_kctf_flow"
    out_dir = Path(args.out or (Path(input_path).parent / default_out)).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "pseudocode").mkdir(exist_ok=True)
    (out_dir / "graphs").mkdir(exist_ok=True)
    (out_dir / "switch_view").mkdir(exist_ok=True)

    ranking = discover_candidates(args.top, args.min_score)
    targets = choose_targets(args, ranking)
    if not targets:
        raise RuntimeError("no analyzable function selected")

    # Reuse already-built profiles from ranking where possible.
    profile_by_ea = {item["ea"]: item for item in ranking}
    functions: List[Dict[str, Any]] = []
    for index, ea in enumerate(targets, 1):
        profile = profile_by_ea.get(ea) or profile_function(ea)
        log("analyzing %d/%d %s" % (index, len(targets), profile["name"]))
        ctree = (
            {"available": False, "error": "disabled by --no-hexrays"}
            if args.no_hexrays
            else decompile_control(ea, args.annotate)
        )
        function = dict(profile)
        function["ctree"] = ctree
        if args.annotate:
            for command in function["cfg"].get("recovered_commands", []):
                comment = "[KCTF] cmd %s -> %s" % (
                    command["command_hex"], command["action"]
                )
                ida_bytes.set_cmt(command["site_ea"], comment, False)
        if args.label_commands:
            for command in function["cfg"].get("recovered_commands", []):
                target_ea = command["target_ea"]
                current_flags = ida_bytes.get_flags(target_ea)
                if ida_bytes.has_user_name(current_flags):
                    continue
                action = command["action"].lower().replace("/", "_")
                label = "kctf_cmd_%x_%s" % (command["command"], action)
                ida_name.set_name(target_ea, label, ida_name.SN_CHECK)
        stem = "%s_%x" % (safe_filename(profile["name"]), ea)
        if ctree.get("available"):
            (out_dir / "pseudocode" / (stem + ".c")).write_text(
                ctree["pseudocode"] + "\n", encoding="utf-8"
            )
            commands = function["cfg"].get("recovered_commands", [])
            if commands and not args.no_switch_view:
                switch_result = rewrite_to_switch(ctree["pseudocode"], commands)
                switch_meta = {
                    key: value for key, value in switch_result.items()
                    if key != "rewritten"
                }
                if switch_result.get("success"):
                    relative_path = "switch_view/%s_switch.c" % stem
                    (out_dir / relative_path).write_text(
                        switch_result["rewritten"], encoding="utf-8"
                    )
                    switch_meta["relative_path"] = relative_path
                    (out_dir / "switch_view" / (stem + "_switch.meta.json")).write_text(
                        json.dumps(switch_meta, indent=2, ensure_ascii=False),
                        encoding="utf-8",
                    )
                function["switch_view"] = switch_meta
        functions.append(function)
        (out_dir / "graphs" / (stem + ".dot")).write_text(
            render_dot(function), encoding="utf-8"
        )

    report = {
        "schema_version": 1,
        "script_version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_path": input_path,
        "input_sha256": input_sha256(input_path),
        "candidate_ranking": ranking,
        "functions": functions,
    }
    json_path = out_dir / "report.json"
    md_path = out_dir / "report.md"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")
    if args.save_idb:
        idc.save_database(idc.get_idb_path(), 0)
    log("wrote %s" % md_path)
    log("wrote %s" % json_path)
    return report


def main() -> int:
    args = parse_args(idc.ARGV[1:])
    try:
        report = execute(args)
        log("done: %d function(s)" % len(report["functions"]))
        return 0
    except SystemExit:
        raise
    except Exception as exc:
        log("ERROR: %s: %s" % (type(exc).__name__, exc))
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = main()
    if "--batch" in idc.ARGV[1:]:
        ida_pro.qexit(exit_code)
