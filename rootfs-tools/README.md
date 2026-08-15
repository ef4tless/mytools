# RootFS Tools

用于 CTF / kernel-pwn / initramfs 根文件系统镜像（`rootfs.img`、`rootfs.ext2/3/4`、cpio 及其 gzip/xz/zstd/lz4 压缩变体）的检测、解包、修改与重打包工作流。

## 用法

- 推荐直接使用 `PATH` 中的 `rootfs-tools`；
- 如果环境里没有安装，使用本目录下的 `scripts/rootfs-tools`。

运行前先 `file IMAGE` 确认镜像格式。支持 ext2/ext3/ext4、纯 cpio、以及 gzip/xz/zstd/lz4 压缩的 cpio 归档。

> 注意：不支持 squashfs 镜像，请改用 `unsquashfs` / `binwalk` 等固件专用工具。

## 内容

- `SKILL.md` — 完整使用说明（CTF 场景下的解包 → 修改 → 重打包流程）
- `scripts/rootfs-tools` — 核心脚本（851 行）
- `agents/openai.yaml` — Agent 接口描述
