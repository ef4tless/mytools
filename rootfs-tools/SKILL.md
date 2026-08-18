---
name: rootfs-tools
description: Use when working on CTF, kernel-pwn, or initramfs/root filesystem artifacts such as `rootfs.img`, `rootfs.ext4`, `rootfs.ext3`, `rootfs.ext2`, `rootfs.cpio`, or compressed cpio archives. Use it to detect the image type, unpack into a writable workdir, inspect challenge files, rebuild `exp`, restore `/init`, repack the filesystem, and regenerate helper run scripts with the local `rootfs-tools` workflow.
---

# RootFS Tools

Use `rootfs-tools` to unpack and repack challenge root filesystems without manually rebuilding
cpio or ext4 images.

## Tool Selection

- Prefer `rootfs-tools` from `PATH`.
- If it is missing, use `scripts/rootfs-tools` from this skill.
- Run `file IMAGE` before unpacking to confirm the format.

## Supported Inputs

- Raw ext2, ext3, and ext4 images, including common `rootfs.img` files
- Plain `cpio`
- `gzip`, `xz`, `zstd`, and `lz4` compressed cpio archives

Do not use this workflow for squashfs images. Switch to `unsquashfs`, `binwalk`, or another
firmware-specific extraction path instead.

## Workflow

1. Find candidate filesystem artifacts near the challenge files.

   ```bash
   rg --files | rg 'rootfs|initramfs|cpio|\.img$|\.ext[234]$'
   ```

2. Resolve the tool once and reuse it.

   ```bash
   TOOL=rootfs-tools
   command -v "$TOOL" >/dev/null 2>&1 || TOOL=/path/to/this/skill/scripts/rootfs-tools
   ```

3. Unpack the image into a workdir next to the original file.

   ```bash
   "$TOOL" open rootfs.img
   ```

4. Refresh an existing workdir when you want a clean re-extract.

   ```bash
   "$TOOL" open --force rootfs.img
   ```

5. Work inside `IMAGE_STEM.work/fs/`.

6. Repack the modified filesystem.

   ```bash
   "$TOOL" pack rootfs.img
   ```

7. Rebuild and inject an explicit exploit binary when needed.

   ```bash
   "$TOOL" pack rootfs.img ./exp.c
   ```

8. Skip compilation and inject a prebuilt `exp` directly when you already have one.

   ```bash
   "$TOOL" pack rootfs.img --use-exp ./exp
   ```

9. Restore the original `/init` before rebuilding when your edits touched boot flow.

   ```bash
   "$TOOL" pack rootfs.img --restore-init
   ```

10. Rebuild from the pristine source tree and inject only the new `exp` when you want to avoid
   carrying other filesystem edits.

   ```bash
   "$TOOL" pack rootfs.img --pristine
   ```

If `exp.c` lives next to the original image, `pack` auto-builds it into `/exp` with default
`musl-gcc -static -lpthread -idirafter /usr/include/ -idirafter /usr/include/x86_64-linux-gnu/`.
Append extra flags with `EXTRA_CFLAGS=...` when needed. If you already have a compiled `exp`,
use `--use-exp ./exp` to skip compilation and copy it directly into the filesystem.

## Outputs

- `IMAGE_STEM.work/fs/`: unpacked filesystem tree
- `IMAGE_STEM.work/backup/`: original `/init` backup when present
- `IMAGE_STEM.work/out/`: rebuilt images
- `run.debug.sh` next to the original image when a local `run.sh` exists
- `run.debug.gdb` when `vmlinux` and a module are present

## Verification

- Confirm unpack success by checking that `...work/fs/` contains expected directories such as
  `bin`, `etc`, `root`, and `sbin`.
- Confirm repack success with `file OUTPUT_IMAGE`.
- Inspect `run.debug.sh` to verify that the boot image path points to the rebuilt artifact.
- Expect `mke2fs` to warn about 128-byte inodes on older ext filesystems. Treat that as normal
  unless the rebuild fails.

## CTF Notes

- Search the unpacked tree for `flag`, `init`, `run.sh`, `.ko`, `vmlinux`, and custom startup
  files first.
- Inspect `/root`, `/home/ctf`, `/etc/init.d`, `/etc/inittab`, `/sbin/init`, and kernel modules
  early on kernel-pwn challenges.
- Avoid editing the original image directly. Work from the `.work` tree and rebuilt outputs.

## Bundled Resource

- `scripts/rootfs-tools`: canonical unpack/repack tool used by the skill; point
  `/usr/local/bin/rootfs-tools` here when you want manual and agent usage to stay identical
