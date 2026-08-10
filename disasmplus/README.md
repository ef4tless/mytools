# disasmplus: Kernel CTF Flow

面向 Linux 内核 CTF 模块的 IDA/IDAPython 插件。它结合 IDA CFG、Hex-Rays ctree 和确定性规则，把大型 `ioctl`/`read`/`write` handler 中的命令分发逻辑整理成更易读的 switch 视图和分析报告，全程无需联网或调用大模型。

## 快速安装

要求：IDA 9.x（当前版本在 IDA Professional 9.4 上验证）和 Python 3。

```bash
cd disasmplus
python3 install_ida_plugin.py
```

安装脚本默认写入 `~/.idapro/plugins`。需要安装到其他位置时：

```bash
python3 install_ida_plugin.py --plugin-dir /path/to/ida/plugins
```

重启 IDA 后，把光标放在目标函数的反汇编或伪代码窗口内，然后使用任一入口：

- 按 `Option+Shift+F5`（IDA 中显示为 `Alt-Shift-F5`）；
- 右键选择 `Kernel CTF -> Kernel CTF: Show switch-oriented C`；
- 选择 `Edit -> Plugins -> Kernel CTF Switch View`。

## 目录结构

```text
disasmplus/
├── ida_kernel_ctf_flow.py             # IDAPython 分析器与无头运行入口
├── kctf_switch_rewriter.py            # 确定性 if/switch 重写器
├── install_ida_plugin.py              # 用户级插件安装器
├── ida_plugin/
│   ├── kernel_ctf_flow_plugin.py       # IDA GUI 插件入口
│   └── kernel_ctf_flow_lib/__init__.py
└── tests/test_switch_rewriter.py       # 不依赖 IDA 的重写器单元测试
```

仓库仅保留插件源码和可独立运行的单元测试；本地样本、IDA 数据库、分析日志、解包文件和生成报告均未纳入版本控制。

## 在 IDA GUI 中运行脚本

1. 在 IDA 中打开 `.ko`，等待自动分析完成。
2. 将光标放到 `ioctl`、`read`、`write` 等目标函数内。
3. 选择 `File -> Script file...`，打开 `ida_kernel_ctf_flow.py`。
4. 默认分析当前函数，并在输入文件旁生成 `<sample>_kctf_flow/`。

输出结构：

```text
<sample>_kctf_flow/
├── report.md
├── report.json
├── pseudocode/*.c
├── switch_view/*_switch.c
└── graphs/*.dot
```

## 无头运行

```bash
IDA="/Applications/IDA Professional 9.4.app/Contents/MacOS/idat"
SCRIPT="$PWD/ida_kernel_ctf_flow.py"
INPUT="/path/to/module.ko"
OUT="/path/to/output"

"$IDA" -A \
  -S"$SCRIPT --discover --top 8 --min-score 6 --batch --out $OUT" \
  "$INPUT"
```

也可以指定一个或多个函数：

```bash
"$IDA" -A \
  -S"$SCRIPT --func target_ioctl --annotate --label-commands --save-idb --batch --out $OUT" \
  "$INPUT"
```

## 插件行为

插件会创建可停靠的 `Kernel CTF Switch View` 窗口，并自动跟随反汇编或伪代码窗口中的当前函数：

- `F`：暂停或恢复自动跟随；
- `R`：强制刷新；
- 双击 `case`：跳转到对应命令入口；
- 关闭窗口：停止跟随。

每次运行会在二进制所在目录保存：

```text
<binary-dir>/<binary-name>_kctf_flow/
├── manifest.json
└── switch_view/
    ├── <function>_<ea>_switch.c
    └── <function>_<ea>_switch.meta.json
```

## 命令行参数

| 参数 | 作用 |
| --- | --- |
| `--func NAME_OR_EA` | 指定函数，可重复使用 |
| `--discover` | 使用确定性评分发现 handler |
| `--top N` | 最多保留 N 个候选，默认 12 |
| `--min-score N` | 设置候选最低分，默认 6 |
| `--out DIR` | 设置报告输出目录 |
| `--annotate` | 给 if/switch 地址写入 `[KCTF]` 注释 |
| `--label-commands` | 将命令入口命名为 `kctf_cmd_<值>_<动作>` |
| `--save-idb` | 保存 IDB 修改 |
| `--no-hexrays` | 仅使用汇编 CFG |
| `--no-switch-view` | 不生成 switch 化伪代码 |
| `--batch` | 分析完成后退出 IDA |

## 运行测试

重写器测试不依赖 IDA：

```bash
cd disasmplus
python3 -m unittest discover -s tests -v
```

## 分析方法

脚本使用三类可审计信息：

1. **IDA CFG**：基本块、条件边、汇合点、分支独占区域和圈复杂度。
2. **Hex-Rays ctree**：`if` 条件、嵌套深度、`switch/case`、分支调用和字符串。
3. **确定性规则**：识别用户态拷贝、分配释放、锁和引用计数等内核 API，并解码常见 Linux `_IOC` 命令值。

推荐先阅读 `report.md` 的候选排名与命令分支，再对照 `switch_view/`、伪代码和 CFG 确认数据流。`_IOC` 解码采用 Linux 通用位布局；目标架构覆盖该布局时，以对应内核头文件为准。
