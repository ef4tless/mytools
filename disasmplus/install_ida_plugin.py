#!/usr/bin/env python3
"""Install/update Kernel CTF Switch View in the current user's IDA plugins."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SOURCE_ENTRY = ROOT / "ida_plugin" / "kernel_ctf_flow_plugin.py"
SOURCE_INIT = ROOT / "ida_plugin" / "kernel_ctf_flow_lib" / "__init__.py"
SOURCE_MODULES = [ROOT / "ida_kernel_ctf_flow.py", ROOT / "kctf_switch_rewriter.py"]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--plugin-dir",
        type=Path,
        default=Path.home() / ".idapro" / "plugins",
        help="IDA user plugin directory",
    )
    args = parser.parse_args()
    plugin_dir = args.plugin_dir.expanduser().resolve()
    lib_dir = plugin_dir / "kernel_ctf_flow_lib"
    plugin_dir.mkdir(parents=True, exist_ok=True)
    lib_dir.mkdir(parents=True, exist_ok=True)

    sources = [SOURCE_ENTRY, SOURCE_INIT, *SOURCE_MODULES]
    for source in sources:
        if not source.is_file():
            raise FileNotFoundError(source)

    destinations = {
        SOURCE_ENTRY: plugin_dir / "kernel_ctf_flow_plugin.py",
        SOURCE_INIT: lib_dir / "__init__.py",
        SOURCE_MODULES[0]: lib_dir / SOURCE_MODULES[0].name,
        SOURCE_MODULES[1]: lib_dir / SOURCE_MODULES[1].name,
    }
    for source, destination in destinations.items():
        shutil.copy2(source, destination)

    manifest = {
        "name": "Kernel CTF Switch View",
        "version": "0.5.0",
        "installed_at": datetime.now(timezone.utc).isoformat(),
        "source_root": str(ROOT),
        "files": {
            str(destination.relative_to(plugin_dir)): {
                "sha256": sha256(destination),
                "source": str(source),
            }
            for source, destination in destinations.items()
        },
    }
    manifest_path = lib_dir / "install-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    print("OK: installed Kernel CTF Switch View v0.5.0")
    print("entry: %s" % destinations[SOURCE_ENTRY])
    print("manifest: %s" % manifest_path)
    print("hotkey: Alt-Shift-F5")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
