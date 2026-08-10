#!/usr/bin/env python3
"""IDA GUI plugin for deterministic kernel-CTF switch reconstruction."""

from __future__ import annotations

import json
import re
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import ida_auto
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_lines
import ida_loader
import ida_nalt


PLUGIN_VERSION = "0.5.0"
ACTION_NAME = "disasmplus:kctf_switch_current"
ACTION_LABEL = "Kernel CTF: Show switch-oriented C"
ACTION_HOTKEY = "Alt-Shift-F5"
VIEW_TITLE = "Kernel CTF Switch View"
FOLLOW_DELAY_MS = 250
LIB_DIR = Path(__file__).resolve().parent / "kernel_ctf_flow_lib"
if str(LIB_DIR) not in sys.path:
    sys.path.insert(0, str(LIB_DIR))

import ida_kernel_ctf_flow as flow  # noqa: E402
from kctf_switch_rewriter import rewrite_to_switch  # noqa: E402


def _msg(text: str) -> None:
    ida_kernwin.msg("[KCTF-SWITCH] %s\n" % text)


def _current_ea(ctx: Optional[Any] = None) -> int:
    if ctx is not None:
        try:
            ea = int(ctx.cur_ea)
            if ea != ida_idaapi.BADADDR:
                return ea
        except Exception:
            pass
    return int(ida_kernwin.get_screen_ea())


def _binary_anchor() -> Path:
    input_path = ida_nalt.get_input_file_path()
    idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    return Path(input_path or idb_path or Path.home() / "kernel_ctf")


def _artifact_root() -> Path:
    anchor = _binary_anchor()
    parent = anchor.parent if anchor.parent.exists() else Path.home()
    sample_name = flow.safe_filename(anchor.stem or "kernel_ctf")
    out = parent / (sample_name + "_kctf_flow")
    try:
        out.mkdir(parents=True, exist_ok=True)
        return out
    except OSError:
        fallback = Path.home() / ".idapro" / "kctf_flow" / sample_name
        fallback.mkdir(parents=True, exist_ok=True)
        _msg("binary directory is not writable; using %s" % fallback)
        return fallback


def _output_root() -> Path:
    out = _artifact_root() / "switch_view"
    out.mkdir(parents=True, exist_ok=True)
    return out


def _atomic_write_text(path: Path, text: str) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)


def _relative_or_absolute(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _update_artifact_manifest(
    artifact_root: Path,
    c_path: Path,
    meta_path: Path,
    metadata: Dict[str, Any],
) -> Path:
    manifest_path = artifact_root / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        manifest = {}
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        artifacts = {}
    key = "0x%x" % metadata["function"]["ea"]
    detail = metadata["switch_view"]["detail_validation"]
    artifacts[key] = {
        "function": metadata["function"],
        "c_path": _relative_or_absolute(c_path, artifact_root),
        "meta_path": _relative_or_absolute(meta_path, artifact_root),
        "command_count": len(metadata["commands"]),
        "occurrence_coverage": detail["occurrence_coverage"],
        "switch_view_sha256": metadata["switch_view"]["switch_view_sha256"],
    }
    manifest = {
        "schema_version": 1,
        "plugin_version": PLUGIN_VERSION,
        "binary_path": str(_binary_anchor()),
        "binary_sha256": flow.input_sha256(str(_binary_anchor())),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "artifacts": dict(sorted(artifacts.items())),
    }
    _atomic_write_text(
        manifest_path,
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
    )
    return manifest_path


C_KEYWORDS = {
    "break", "case", "const", "continue", "default", "do", "else", "enum",
    "for", "goto", "if", "return", "sizeof", "struct", "switch", "typedef",
    "union", "while", "volatile", "signed", "unsigned", "void", "char",
    "short", "int", "long", "float", "double", "bool", "true", "false",
    "nullptr", "NULL", "__int8", "__int16", "__int32", "__int64",
    "__fastcall", "__cdecl", "__stdcall",
}


def _colored(text: str, color: str) -> str:
    return ida_lines.COLSTR(text, color)


def colorize_c_line(line: str) -> str:
    """Apply IDA color tags while preserving the exact visible C text."""
    stripped = line.lstrip()
    if stripped.startswith(("//", "/*", "*", "*/")):
        return _colored(line, ida_lines.SCOLOR_REGCMT)
    if stripped.startswith("#"):
        return _colored(line, ida_lines.SCOLOR_ASMDIR)

    result = []
    index = 0
    length = len(line)
    while index < length:
        if line.startswith("//", index):
            result.append(_colored(line[index:], ida_lines.SCOLOR_REGCMT))
            break
        char = line[index]
        if char in ('"', "'"):
            quote = char
            end = index + 1
            while end < length:
                if line[end] == "\\":
                    end += 2
                    continue
                end += 1
                if line[end - 1] == quote:
                    break
            color = ida_lines.SCOLOR_STRING if quote == '"' else ida_lines.SCOLOR_CHAR
            result.append(_colored(line[index:end], color))
            index = end
            continue
        if char.isdigit():
            match = re.match(r"(?:0[xX][0-9A-Fa-f]+|\d+)(?:[uUlL]+)?", line[index:])
            if match:
                token = match.group(0)
                result.append(_colored(token, ida_lines.SCOLOR_NUMBER))
                index += len(token)
                continue
        if char.isalpha() or char == "_":
            match = re.match(r"[A-Za-z_][A-Za-z0-9_]*", line[index:])
            assert match is not None
            token = match.group(0)
            after = index + len(token)
            lookahead = after
            while lookahead < length and line[lookahead].isspace():
                lookahead += 1
            if token in C_KEYWORDS:
                color = ida_lines.SCOLOR_KEYWORD
            elif token.startswith("LABEL_") or (
                lookahead < length and line[lookahead] == ":"
            ):
                color = ida_lines.SCOLOR_LOCNAME
            elif lookahead < length and line[lookahead] == "(":
                color = ida_lines.SCOLOR_CNAME
            else:
                result.append(token)
                index = after
                continue
            result.append(_colored(token, color))
            index = after
            continue
        if char in "{}[]();,:+-*/%&|^!~=<>?":
            result.append(_colored(char, ida_lines.SCOLOR_SYMBOL))
        else:
            result.append(char)
        index += 1
    return "".join(result)


def generate_switch_for_ea(func_ea: int, output_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Generate and persist a switch-oriented view for one function.

    This function contains no GUI operations so the installed plugin can be
    regression-tested under idat as well as called from the interactive action.
    """
    ida_auto.auto_wait()
    func = ida_funcs.get_func(int(func_ea))
    if func is None:
        raise ValueError("address 0x%x is not inside a function" % int(func_ea))
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays decompiler is not available")

    ea = int(func.start_ea)
    name = flow.safe_name(ea)
    cfg = flow.build_cfg(ea)
    ctree = flow.decompile_control(ea, annotate=False)
    if not ctree.get("available"):
        raise RuntimeError("decompilation failed: %s" % ctree.get("error", "unknown error"))
    commands = cfg.get("recovered_commands", [])
    if not commands:
        raise RuntimeError("no repeated command dispatcher found in %s" % name)

    result = rewrite_to_switch(ctree["pseudocode"], commands)
    if not result.get("success"):
        raise RuntimeError(result.get("reason", "switch reconstruction failed"))

    out = Path(output_dir) if output_dir is not None else _output_root()
    out.mkdir(parents=True, exist_ok=True)
    artifact_root = out.parent if out.name == "switch_view" else out
    stem = "%s_%x_switch" % (flow.safe_filename(name), ea)
    c_path = out / (stem + ".c")
    meta_path = out / (stem + ".meta.json")
    _atomic_write_text(c_path, result["rewritten"])

    metadata = {
        "plugin_version": PLUGIN_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_path": ida_nalt.get_input_file_path(),
        "input_sha256": flow.input_sha256(ida_nalt.get_input_file_path() or ""),
        "function": {"ea": ea, "name": name},
        "cfg": {
            key: cfg[key]
            for key in ("block_count", "edge_count", "branch_count", "cyclomatic_complexity")
        },
        "commands": [
            {
                "command": item["command"],
                "command_hex": item["command_hex"],
                "action": item["action"],
                "fourcc_le": item.get("fourcc_le"),
                "target_ea": item["target_ea"],
            }
            for item in commands
        ],
        "switch_view": {key: value for key, value in result.items() if key != "rewritten"},
        "c_path": str(c_path),
    }
    _atomic_write_text(
        meta_path,
        json.dumps(metadata, indent=2, ensure_ascii=False) + "\n",
    )
    manifest_path = _update_artifact_manifest(
        artifact_root, c_path, meta_path, metadata
    )
    return {
        "function_ea": ea,
        "function_name": name,
        "source": ctree["pseudocode"],
        "rewritten": result["rewritten"],
        "switch_view": metadata["switch_view"],
        "commands": metadata["commands"],
        "c_path": str(c_path),
        "meta_path": str(meta_path),
        "manifest_path": str(manifest_path),
    }


class SwitchCodeViewer(ida_kernwin.simplecustviewer_t):
    def __init__(self, plugin: "KernelCTFSwitchPlugin") -> None:
        super().__init__()
        self.source_path = ""
        self.plugin = plugin
        self.function_ea: Optional[int] = None
        self.base_status = ""
        self.command_targets: Dict[int, int] = {}

    def Create(self) -> bool:
        return bool(ida_kernwin.simplecustviewer_t.Create(self, VIEW_TITLE))

    def SetContent(
        self,
        text: str,
        source_path: str,
        status: str,
        function_ea: Optional[int],
        commands: Optional[list] = None,
    ) -> None:
        self.source_path = source_path
        self.function_ea = function_ea
        self.base_status = status
        self.command_targets = {
            int(item["command"]): int(item["target_ea"])
            for item in (commands or [])
            if item.get("target_ea") is not None
        }
        self.ClearLines()
        self.AddLine(self._status_line())
        self.AddLine("")
        for line in text.splitlines():
            self.AddLine(colorize_c_line(line))
        self.Refresh()

    def _status_line(self) -> str:
        mode = "AUTO-FOLLOW" if self.plugin.follow_enabled else "PAUSED"
        text = "// %s | %s | [F] follow  [R] refresh  [double-click case] jump" % (
            mode,
            self.base_status,
        )
        return _colored(text, ida_lines.SCOLOR_AUTOCMT)

    def RefreshStatus(self) -> None:
        if self.Count() > 0:
            self.EditLine(0, self._status_line())
            self.RefreshCurrent()

    def OnKeydown(self, vkey: int, shift: int) -> bool:
        if vkey == ida_kernwin.IK_ESCAPE:
            self.Close()
            return True
        if vkey in (ord("F"), ord("f")):
            self.plugin.toggle_follow()
            return True
        if vkey in (ord("R"), ord("r")) and self.function_ea is not None:
            self.plugin.show_for_ea(self.function_ea, from_follow=False)
            return True
        return False

    def OnDblClick(self, shift: int) -> bool:
        line = self.GetCurrentLine(notags=1) or ""
        match = re.search(r"\bcase\s+(0[xX][0-9A-Fa-f]+|\d+)\s*:", line)
        if match:
            value = int(match.group(1), 0)
            target = self.command_targets.get(value)
            if target is not None:
                ida_kernwin.jumpto(target)
                return True
        return False

    def OnHint(self, lineno: int):
        return (1, "Generated file: %s" % self.source_path)

    def OnClose(self) -> None:
        self.plugin._viewer_closed(self)


class SwitchActionHandler(ida_kernwin.action_handler_t):
    def __init__(self, plugin: "KernelCTFSwitchPlugin") -> None:
        super().__init__()
        self.plugin = plugin

    def activate(self, ctx) -> int:
        self.plugin.show_for_ea(_current_ea(ctx), from_follow=False)
        return 1

    def update(self, ctx) -> int:
        widget_type = ida_kernwin.get_widget_type(ctx.widget) if ctx.widget else -1
        if widget_type not in (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE):
            return ida_kernwin.AST_DISABLE_FOR_WIDGET
        return (
            ida_kernwin.AST_ENABLE_FOR_WIDGET
            if ida_funcs.get_func(_current_ea(ctx)) is not None
            else ida_kernwin.AST_DISABLE_FOR_WIDGET
        )


class PopupHooks(ida_kernwin.UI_Hooks):
    def __init__(self, plugin: "KernelCTFSwitchPlugin") -> None:
        super().__init__()
        self.plugin = plugin

    def finish_populating_widget_popup(self, widget, popup) -> None:
        if ida_kernwin.get_widget_type(widget) in (
            ida_kernwin.BWN_DISASM,
            ida_kernwin.BWN_PSEUDOCODE,
        ):
            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                ACTION_NAME,
                "Kernel CTF/",
                ida_kernwin.SETMENU_APP,
            )

    def screen_ea_changed(self, ea, prev_ea) -> None:
        self.plugin.schedule_follow(int(ea))

    def current_widget_changed(self, widget, prev_widget) -> None:
        if ida_kernwin.get_widget_type(widget) in (
            ida_kernwin.BWN_DISASM,
            ida_kernwin.BWN_PSEUDOCODE,
        ):
            self.plugin.schedule_follow(int(ida_kernwin.get_screen_ea()))


class KernelCTFSwitchPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX
    comment = "Deterministic switch-oriented C view for kernel CTF handlers"
    help = "Recover command dispatchers and display a complete switch-oriented C view"
    wanted_name = "Kernel CTF Switch View"
    wanted_hotkey = ""

    def __init__(self) -> None:
        super().__init__()
        self.handler: Optional[SwitchActionHandler] = None
        self.hooks: Optional[PopupHooks] = None
        self.viewer: Optional[SwitchCodeViewer] = None
        self.follow_enabled = False
        self.last_function_ea: Optional[int] = None
        self.pending_function_ea: Optional[int] = None
        self.follow_timer = None
        self.follow_callback = None
        self.updating = False

    def init(self):
        if not ida_kernwin.is_idaq():
            return ida_idaapi.PLUGIN_SKIP
        self.handler = SwitchActionHandler(self)
        descriptor = ida_kernwin.action_desc_t(
            ACTION_NAME,
            ACTION_LABEL,
            self.handler,
            ACTION_HOTKEY,
            "Generate a full-detail switch-oriented C view for the current function",
            -1,
        )
        if not ida_kernwin.register_action(descriptor):
            _msg("action was already registered; replacing stale registration")
            ida_kernwin.unregister_action(ACTION_NAME)
            if not ida_kernwin.register_action(descriptor):
                _msg("failed to register action")
                return ida_idaapi.PLUGIN_SKIP
        self.hooks = PopupHooks(self)
        self.hooks.hook()
        _msg("loaded v%s; highlighted auto-follow view; hotkey %s" % (PLUGIN_VERSION, ACTION_HOTKEY))
        return ida_idaapi.PLUGIN_KEEP

    def _viewer_closed(self, viewer: SwitchCodeViewer) -> None:
        if self.viewer is viewer:
            self.viewer = None
            self.follow_enabled = False
            self.last_function_ea = None
            self.pending_function_ea = None
            if self.follow_timer is not None:
                try:
                    ida_kernwin.unregister_timer(self.follow_timer)
                except Exception:
                    pass
                self.follow_timer = None
                self.follow_callback = None

    def _ensure_viewer(self, origin_title: Optional[str]) -> SwitchCodeViewer:
        if self.viewer is not None:
            return self.viewer
        viewer = SwitchCodeViewer(self)
        if not viewer.Create() or not viewer.Show():
            raise RuntimeError("failed to create IDA switch viewer")
        self.viewer = viewer
        if origin_title:
            try:
                ida_kernwin.set_dock_pos(VIEW_TITLE, origin_title, ida_kernwin.DP_RIGHT)
            except Exception:
                pass
        return viewer

    def toggle_follow(self) -> None:
        if self.viewer is None:
            return
        self.follow_enabled = not self.follow_enabled
        if not self.follow_enabled:
            self.pending_function_ea = None
            if self.follow_timer is not None:
                try:
                    ida_kernwin.unregister_timer(self.follow_timer)
                except Exception:
                    pass
                self.follow_timer = None
                self.follow_callback = None
        self.viewer.RefreshStatus()
        _msg("auto-follow %s" % ("enabled" if self.follow_enabled else "paused"))

    def schedule_follow(self, ea: int) -> None:
        if not self.follow_enabled or self.viewer is None or self.updating:
            return
        widget = ida_kernwin.get_current_widget()
        if widget is None or ida_kernwin.get_widget_type(widget) not in (
            ida_kernwin.BWN_DISASM,
            ida_kernwin.BWN_PSEUDOCODE,
        ):
            return
        func = ida_funcs.get_func(int(ea))
        if func is None:
            return
        func_ea = int(func.start_ea)
        if func_ea == self.last_function_ea:
            self.pending_function_ea = None
            return
        self.pending_function_ea = func_ea
        if self.follow_timer is not None:
            return

        def fire_follow():
            self.follow_timer = None
            target = self.pending_function_ea
            self.pending_function_ea = None
            widget = ida_kernwin.get_current_widget()
            if (
                target is not None
                and self.follow_enabled
                and self.viewer is not None
                and widget is not None
                and ida_kernwin.get_widget_type(widget)
                in (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE)
            ):
                current = ida_funcs.get_func(int(ida_kernwin.get_screen_ea()))
                if current is not None:
                    target = int(current.start_ea)
                if target != self.last_function_ea:
                    self.show_for_ea(target, from_follow=True)
            return -1

        self.follow_callback = fire_follow
        self.follow_timer = ida_kernwin.register_timer(FOLLOW_DELAY_MS, fire_follow)
        if self.follow_timer is None:
            self.follow_callback = None
            target = self.pending_function_ea
            self.pending_function_ea = None
            if target is not None:
                self.show_for_ea(target, from_follow=True)

    def show_for_ea(self, ea: int, from_follow: bool = False) -> Optional[Dict[str, Any]]:
        if self.updating:
            return None
        origin_widget = ida_kernwin.get_current_widget()
        origin_title = ida_kernwin.get_widget_title(origin_widget) if origin_widget else None
        func = ida_funcs.get_func(int(ea))
        requested_func_ea = int(func.start_ea) if func is not None else None
        self.updating = True
        try:
            generated = generate_switch_for_ea(ea)
            func_ea = generated["function_ea"]
            detail = generated["switch_view"]["detail_validation"]
            viewer = self._ensure_viewer(origin_title)
            self.follow_enabled = True
            status = (
                "%s @ 0x%x | %d commands | detail %.2f%% | %s"
                % (
                    generated["function_name"],
                    func_ea,
                    len(generated["commands"]),
                    100.0 * detail["occurrence_coverage"],
                    generated["c_path"],
                )
            )
            viewer.SetContent(
                generated["rewritten"],
                generated["c_path"],
                status,
                func_ea,
                generated["commands"],
            )
            self.last_function_ea = func_ea
            _msg(
                "%s: %d command(s), detail %.2f%%, saved %s"
                % (
                    generated["function_name"],
                    len(generated["commands"]),
                    100.0 * detail["occurrence_coverage"],
                    generated["c_path"],
                )
            )
            return generated
        except Exception as exc:
            _msg("ERROR: %s: %s" % (type(exc).__name__, exc))
            if from_follow:
                try:
                    viewer = self._ensure_viewer(origin_title)
                    name = flow.safe_name(requested_func_ea) if requested_func_ea is not None else "no function"
                    text = "/*\n * No switch-oriented view for %s.\n * %s\n */\n" % (name, exc)
                    viewer.SetContent(
                        text,
                        "",
                        "%s | no dispatcher" % name,
                        requested_func_ea,
                    )
                    self.last_function_ea = requested_func_ea
                except Exception:
                    traceback.print_exc()
            else:
                traceback.print_exc()
                ida_kernwin.warning("Kernel CTF Switch View\n\n%s" % exc)
            return None
        finally:
            self.updating = False

    def run(self, arg: int) -> None:
        self.show_for_ea(_current_ea(), from_follow=False)

    def term(self) -> None:
        if self.hooks is not None:
            self.hooks.unhook()
            self.hooks = None
        if self.follow_timer is not None:
            try:
                ida_kernwin.unregister_timer(self.follow_timer)
            except Exception:
                pass
            self.follow_timer = None
            self.follow_callback = None
        ida_kernwin.unregister_action(ACTION_NAME)
        if self.viewer is not None:
            try:
                self.viewer.Close()
            except Exception:
                pass
            self.viewer = None


def PLUGIN_ENTRY():
    return KernelCTFSwitchPlugin()
