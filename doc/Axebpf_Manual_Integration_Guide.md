# Axebpf 主线手工联调指南

> 适用范围：QEMU AArch64、AxVisor shell、Linux guest、`axebpf` 主线联调
>
> 本文目标：用于手工联调并验证 `uprobe`、`uretprobe`、`guest-kprobe`、`guest-kretprobe`、`hprobe`、`hretprobe`、`tracepoint` 七类能力


---

## 1. 当前结论

当前主线已经可以在同一次 `QEMU + AxVisor + Linux guest` 运行中，联动验证下面七类能力：

1. `uprobe`：`/usr/bin/axebpf_integration_demo:demo_user_entry`
2. `uretprobe`：`/usr/bin/axebpf_integration_demo:demo_user_compute`
3. `guest-kprobe`：`vm1:gic_handle_irq`
4. `guest-kretprobe`：`vm1:__arm64_sys_getpid`
5. `hprobe`：`notify_guest_vmexit`
6. `hretprobe`：`notify_guest_vmexit`
7. `tracepoint`：`vmm:timer_tick`

当前工作流的推荐使用方式是：

- 先完成主机侧准备和全部 attach
- 再一次性启动 guest demo
- 运行中重点看命中日志
- `trace list` 和 `trace stat` 只在 host shell 仍然可交互时作为补充快照使用，不是默认必经步骤

需要特别注意三点：

1. `guest-uprobe/guest-uretprobe` 的命中证据主要看运行期 raw log；guest 进程退出后，`trace list` 中只会保留 `pending` 模板，这是当前实现的正常表现。
2. 当前 guest 会通过 `/etc/inittab` 非交互拉起 demo，本工作流不提供 guest 交互 shell；因此 `demo:done` 之后不应期待回到 guest shell。
3. `hprobe/hretprobe` 挂在 `notify_guest_vmexit` 这种高频路径上；如果运行结束后当前终端仍然回到了 host shell，再执行一次 `trace verbose off` 会更利于抓补充快照。

---

## 2. 主机侧前置准备

先确认当前主线功能已经启用：

```bash
rg -n "hprobe|guest-kprobe|guest-uprobe" \
  /home/iscreamx/vscode/axvisor/.build.toml \
  /home/iscreamx/vscode/axvisor/kernel/Cargo.toml
```

预期至少能看到：

```text
.build.toml:    "hprobe",
.build.toml:    "guest-kprobe",
.build.toml:    "guest-uprobe",
```

再构建 `axvisor`：

```bash
cd /home/iscreamx/vscode/axvisor
cargo xtask build
```

预期结果：

- `target/aarch64-unknown-none-softfloat/release/axvisor`
- `target/aarch64-unknown-none-softfloat/release/axvisor.bin`

再准备联调镜像。这里不限定你使用哪一个本地准备脚本或工作流，只要求后续手工联调依赖的产物已经就位。

可以直接手工确认关键文件：

```bash
ls -l \
  /home/iscreamx/vscode/axvisor/target/aarch64-unknown-none-softfloat/release/axvisor.bin \
  /home/iscreamx/vscode/axvisor/tmp/images/qemu_aarch64_linux/rootfs-linux-axebpf-mainline-integration.img \
  /home/iscreamx/vscode/axvisor/target/bpf/printk.o
```

预期至少满足：

- `axvisor.bin` 已生成
- `rootfs-linux-axebpf-mainline-integration.img` 已存在
- `printk.o` 已存在

如果你本地还没有这份
`rootfs-linux-axebpf-mainline-integration.img`，可以参考
`/home/iscreamx/vscode/axvisor/scripts/axdemo.py` 里
`prepare_linux_base_image()` 对运行时镜像的准备方式，再按你的本地工作流补齐这份
`img`。

---

## 3. 准备 host hprobe 符号

`hprobe/hretprobe` 目标不要手写死，联调前先从当前 `axvisor` ELF 里取一次：

```bash
nm -n /home/iscreamx/vscode/axvisor/target/aarch64-unknown-none-softfloat/release/axvisor \
  | rg "notify_guest_vmexit"
```

当前 fresh 复核结果是：

```text
0000f8000017470c t _RNvNtCsdQH8tYCRzGI_7axvisor3vmm19notify_guest_vmexit
```

下面文档中默认使用：

```text
_RNvNtCsdQH8tYCRzGI_7axvisor3vmm19notify_guest_vmexit
```

如果你当前本地编译结果不一样，以你机器上的 `nm` 输出为准。

---

## 4. 启动 AxVisor Shell

下面直接手工启动 QEMU。这里的磁盘镜像不是凭空来的，而是第 2 节
准备步骤产出的主线联调镜像：

```text
/home/iscreamx/vscode/axvisor/tmp/images/qemu_aarch64_linux/rootfs-linux-axebpf-mainline-integration.img
```

也就是说，这里的 `ROOTFS` 就是上一节已经准备并手工确认过的那份镜像，
不是额外生成的新文件；直接把它挂到 QEMU 的 `-drive ... file=$ROOTFS`
即可。

```bash
AXVISOR_ROOT=/home/iscreamx/vscode/axvisor
AXVISOR_BIN=$AXVISOR_ROOT/target/aarch64-unknown-none-softfloat/release/axvisor.bin
ROOTFS=$AXVISOR_ROOT/tmp/images/qemu_aarch64_linux/rootfs-linux-axebpf-mainline-integration.img

qemu-system-aarch64 \
  -nographic \
  -cpu cortex-a72 \
  -machine virt,virtualization=on,gic-version=3 \
  -smp 4 \
  -device virtio-blk-device,drive=disk0 \
  -drive id=disk0,if=none,format=raw,file=$ROOTFS \
  -append 'root=/dev/vda rw init=/init' \
  -m 8g \
  -kernel $AXVISOR_BIN
```

预期输出中应出现：

```text
Welcome to AxVisor Shell!
axvisor:/$
```

说明：

- 这里启动的是 AxVisor 自身环境，所以 `-append` 仍然是 `init=/init`
- Linux guest 真正的启动参数来自后面 `vm create` 所用的 `/vmconfigs/linux-qemu-smp1-axebpf-integration.toml`
- 该 guest vmconfig 已经固定为 `init=/sbin/init`，并通过 `/etc/inittab` 非交互拉起 demo，避免 guest shell 和 host shell 争串口

---

## 5. 共用准备步骤

下面所有 attach 都必须在 `vm start 1` 之前完成。

### 5.1 打开 verbose

```text
trace verbose on
```

预期输出：

```text
Verbose mode: enabled
```

### 5.2 创建 VM

```text
vm create /vmconfigs/linux-qemu-smp1-axebpf-integration.toml
```

预期输出：

```text
✓ Successfully created VM[1] from config: /vmconfigs/linux-qemu-smp1-axebpf-integration.toml
Successfully created 1 VM(s)
```

### 5.3 加载 Linux guest 符号

```text
trace loadsyms vm1 /vmimages/linux-qemu-aarch64.syms
```

预期输出：

```text
Loaded 69079 symbols for vm1 from '/vmimages/linux-qemu-aarch64.syms'
```

### 5.4 加载 guest demo 用户态 ELF 符号

```text
trace uloadelf vm1 /usr/bin/axebpf_integration_demo /vmimages/axebpf-integration-demo.syms
```

预期输出：

```text
Loaded 14 user symbols for vm1:/usr/bin/axebpf_integration_demo from '/vmimages/axebpf-integration-demo.syms'
```

### 5.5 加载 eBPF 程序

```text
trace load file /vmimages/printk.o shell:shell_command
```

预期输出：

```text
Loaded program 0 (1376 bytes) from /vmimages/printk.o
Attached to shell:shell_command
```

说明：

- 后面所有 probe attach 都直接使用 `prog id = 0`

### 5.6 启用并挂载 tracepoint

```text
trace enable vmm:timer_tick
trace load prog 0 vmm:timer_tick
```

预期输出：

```text
Enabled: vmm:timer_tick
Attached program 0 to vmm:timer_tick
```

---

## 6. 手工 attach 七类能力

### 6.1 attach `hprobe`

```text
trace hprobe _RNvNtCsdQH8tYCRzGI_7axvisor3vmm19notify_guest_vmexit 0
```

预期结果：

- 返回到 prompt
- 不出现 `Error:`

如果你开着 verbose，通常会看到类似日志：

```text
kprobe: registering ...notify_guest_vmexit ... (is_ret=false, prog_id=0)
kprobe: enabled ...notify_guest_vmexit ... (is_ret=false)
```

### 6.2 attach `hretprobe`

```text
trace hretprobe _RNvNtCsdQH8tYCRzGI_7axvisor3vmm19notify_guest_vmexit 0
```

预期结果：

- 返回到 prompt
- 不出现 `Error:`

verbose 下通常能看到：

```text
kprobe: registering ...notify_guest_vmexit ... (is_ret=true, prog_id=0)
kprobe: enabled ...notify_guest_vmexit ... (is_ret=true)
```

### 6.3 attach `guest-kprobe`

```text
trace kprobe vm1:gic_handle_irq 0 --inject
```

预期输出：

```text
kprobe registered pending enable: vm1:0xffff800080010200 -> prog 0 (mode=brk-inject)
```

### 6.4 attach `guest-kretprobe`

```text
trace kprobe vm1:__arm64_sys_getpid 0 --inject --ret
```

预期输出：

```text
kretprobe registered pending enable: vm1:0xffff8000800c6768 -> prog 0 (mode=brk-inject)
```

### 6.5 attach `uprobe`

```text
trace uprobe vm1:/usr/bin/axebpf_integration_demo:demo_user_entry 0
```

预期输出：

```text
uprobe registered pending enable: vm1:/usr/bin/axebpf_integration_demo:demo_user_entry -> prog 0
```

### 6.6 attach `uretprobe`

```text
trace uprobe vm1:/usr/bin/axebpf_integration_demo:demo_user_compute 0 --ret
```

预期输出：

```text
uretprobe registered pending enable: vm1:/usr/bin/axebpf_integration_demo:demo_user_compute -> prog 0
```

---

## 7. 启动前先看一次 `trace list`

在 `vm start 1` 之前先抓一次：

```text
trace list
```

这一步的目的不是看 hits，而是确认：

1. `vmm:timer_tick` 已经是 `enabled`
2. `Hprobes (VMM probes)` 已经有 entry/ret 两行
3. `Guest Kprobes` 已经有：
   - `gic_handle_irq+0x0`
   - `__arm64_sys_getpid+0x0`
4. `Guest Uprobes` 已经有两条 `pending` 模板，`PENDING` 列为 `waiting-for-instance`

你应当至少能看到类似内容：

```text
vmm:timer_tick                 enabled    5

Hprobes (VMM probes):
  ...notify_guest_vmexit ... yes no
  ...notify_guest_vmexit ... yes yes

Guest Kprobes:
  vm1   gic_handle_irq+0x0
  vm1   __arm64_sys_getpid+0x0

Guest Uprobes:
  vm1   /usr/bin/axebpf_integration_demo demo_user_entry   ... pending ... waiting-for-instance
  vm1   /usr/bin/axebpf_integration_demo demo_user_compute ... pending ... waiting-for-instance
```

如果这里就缺行，后面不要继续联调，先检查 attach 是否报错。

---

## 8. 启动 guest 并观察运行期证据

### 8.1 启动 guest

```text
vm start 1
```

预期输出至少包含：

```text
✓ VM[1] started successfully
```

之后不要着急敲别的命令，先看运行期日志。

### 8.2 先看 demo 是否真的拉起

你应当先看到：

```text
axebpf_integration_demo wrapper: launch
demo:start
phase4:repeat_window begin
phase1:userspace_fn begin
```

如果没有 `wrapper: launch` 或 `demo:start`，通常说明 guest demo 没有按 `inittab` 被拉起。

### 8.3 看 `hprobe/hretprobe`

运行过程中应能看到类似下面的样本日志：

```text
[hprobe] ENTRY _RNvNtCsdQH8tYCRzGI_7axvisor3vmm19notify_guest_vmexit hit=1 sampled=false ...
[hprobe] EXIT  _RNvNtCsdQH8tYCRzGI_7axvisor3vmm19notify_guest_vmexit hit=1 sampled=false ...
[hprobe] ENTRY _RNvNtCsdQH8tYCRzGI_7axvisor3vmm19notify_guest_vmexit hit=256 sampled=true ...
[hprobe] EXIT  _RNvNtCsdQH8tYCRzGI_7axvisor3vmm19notify_guest_vmexit hit=256 sampled=true ...
```

只要 `ENTRY/EXIT` 两类日志都出现，就说明 `hprobe` 和 `hretprobe` 都已经命中；`sampled=true` 只是说明它属于抽样输出，不代表异常。

### 8.4 看 `guest-kprobe`

运行中会出现类似：

```text
guest_kprobe_hits: kprobe vm1:gic_handle_irq hits=1
guest_kprobe_hits: kprobe vm1:gic_handle_irq hits=2
guest_kprobe_hits: kprobe vm1:gic_handle_irq hits=4
```

说明 `guest-kprobe` 已经命中。

### 8.5 看 `guest-kretprobe`

运行中会出现类似：

```text
guest_kprobe_hits: kretprobe vm1:__arm64_sys_getpid hits=1
guest_kprobe_hits: kretprobe vm1:__arm64_sys_getpid hits=2
```

说明 `guest-kretprobe` 已经命中。

### 8.6 看 `uprobe`

运行期应出现：

```text
guest_uprobe_hit: vm1 path=/usr/bin/axebpf_integration_demo symbol=demo_user_entry ...
```

这条日志是 `uprobe` 的最关键证据。

说明：

- fresh 复核中，demo 刚拉起时还可能短暂看到两条类似

```text
guest_uprobe: activate pending vm1:/usr/bin/axebpf_integration_demo+... failed: failed to translate user VA->GPA
```

- 这通常发生在用户态映射刚建立、对应页还没能立刻翻译时。
- 只要后面实际出现了 `guest_uprobe_hit` 和 `guest_uretprobe_hit`，这两条 warning 不应判为失败。

### 8.7 看 `uretprobe`

运行期应出现：

```text
guest_uretprobe_arm: vm1 path=/usr/bin/axebpf_integration_demo symbol=demo_user_compute ...
guest_uretprobe_hit: vm1 path=/usr/bin/axebpf_integration_demo symbol=demo_user_compute ...
```

这里：

- `arm` 说明 entry 时已经把返回点压栈
- `hit` 说明返回点已经被真正命中

### 8.8 看 guest 是否正常跑完

guest demo 正常结束时应看到：

```text
phase4:repeat_window end
demo:done
```

到这里说明 guest demo 主流程已经跑完。

需要注意：

- 这不代表 guest 会回到交互 shell；当前工作流默认没有 guest shell。
- 这也不保证当前终端一定会重新出现 `axvisor:/$` prompt；如果 prompt 没回来，后续不要再把 `trace list` / `trace stat` 当作必做步骤。

---

## 9. 可选收尾快照（仅当 host shell 仍可交互时）

本节不是默认成功判定的必要条件。

如果 `demo:done` 之后当前终端没有重新出现 `axvisor:/$`，说明这次运行里你拿不到可交互的 host shell；此时直接以第 8 节中的运行期日志作为验收依据，不要继续等待 guest shell，因为本工作流本来就不会返回 guest shell。

### 9.1 先关闭 verbose

只有在当前终端已经重新出现 `axvisor:/$`，并且确认你仍在 host AxVisor shell 时，才执行：

```text
trace verbose off
```

预期输出：

```text
Verbose mode: disabled
```

### 9.2 看最终 `trace list`

```text
trace list
```
应能看到：

```text
Hprobes (VMM probes):
  _RNvNtCsdQH8tYCRzGI_7axvisor3vmm19notify_guest_vmexit ... >0 ... yes no
  _RNvNtCsdQH8tYCRzGI_7axvisor3vmm19notify_guest_vmexit ... >0 ... yes yes

Guest Kprobes:
  vm1   gic_handle_irq+0x0         >0 ...
  vm1   __arm64_sys_getpid+0x0     >0 ...
```

说明：

- 命中数会随 guest 运行窗口和收尾时机变化，不要拿固定数字做唯一判定条件。
- fresh 复核里，`trace list` 前还可能夹着几条 `guest_uprobe_observer_exit_mmap` 或 `guest_uprobe_deactivate_mm`，这是 demo 进程退出后的正常清理日志。

同时，`Guest Uprobes` 区域会看到：

```text
vm1 /usr/bin/axebpf_integration_demo demo_user_entry   ... pending ... waiting-for-instance
vm1 /usr/bin/axebpf_integration_demo demo_user_compute ... pending ... waiting-for-instance
```

这不是失败，而是因为 guest demo 已经退出，运行实例已经被回收。

### 9.3 看最终 `trace stat`

```text
trace stat
```

你应重点看三块：

第一块，`PROBE STATISTICS`：

```text
hprobe     ...
uprobe     ...
uretprobe  ...
kprobe     ...
kretprobe  ...
```

这些项的 `COUNT` 都应大于 0。

第二块，`EBPF ATTACHMENTS`：

```text
vmm:timer_tick   0 custom active
...notify_guest_vmexit   0 2687 active
...notify_guest_vmexit   0 2687 active
```

第三块，`MAP DATA`：

```text
vmm:timer_tick COUNTER_MAP ...
```

只要 `vmm:timer_tick` 对应的 `VALUE` 不是 0，就说明 tracepoint 不只是 attach 了，而且确实有事件流过。

---

## 10. 常见失败点

### 10.1 `trace uloadelf` 或 `trace uprobe` 报 `feature not enabled`

说明当前产物没有打开 `guest-uprobe` 或 `fs`。

先检查：

```bash
rg -n "guest-uprobe|fs|hprobe" \
  /home/iscreamx/vscode/axvisor/.build.toml \
  /home/iscreamx/vscode/axvisor/kernel/Cargo.toml
```

### 10.2 `hprobe` 完全没有命中

优先检查两件事：

1. 当前 `notify_guest_vmexit` 的 mangled symbol 是否和文档一致
2. attach 时是否用了 `prog id = 0`

先重新跑：

```bash
nm -n /home/iscreamx/vscode/axvisor/target/aarch64-unknown-none-softfloat/release/axvisor \
  | rg "notify_guest_vmexit"
```

### 10.3 没看到 `demo:start`

优先检查 rootfs 是否真的被注入了 launcher 和 `inittab`：

```bash
bash /home/iscreamx/vscode/axvisor/scripts/verify/check_linux_axebpf_integration_demo_rootfs.sh \
  /home/iscreamx/vscode/axvisor/tmp/images/qemu_aarch64_linux/rootfs-linux-axebpf-mainline-integration.img
```

### 10.4 `trace list` 最后没有 `active` 的 guest uprobes

这是当前实现下的正常现象，不要误判为失败。

正确判断方式是：

- 运行期看 `guest_uprobe_hit`
- 运行期看 `guest_uretprobe_hit`
- 如果第 9 节条件成立，再看收尾模板是否仍为 `PENDING=waiting-for-instance`

### 10.5 `demo:done` 之后没有回到 `axvisor:/$`

这在当前工作流下不应直接判为异常。

需要先区分两件事：

- 当前 guest 本来就没有交互 shell，所以这里不应期待“回到 guest shell”。
- `trace list`、`trace stat` 这些收尾命令，只能在 host AxVisor shell prompt 重新出现时执行；如果 prompt 没回来，本次验收就以运行期日志为准。

因此本工作流的默认成功标准是：

- 看到了 `demo:start`
- 看到了 `guest_uprobe_hit`
- 看到了 `guest_uretprobe_hit`
- 看到了 `guest_kprobe_hits`
- 看到了 `[hprobe] ENTRY/EXIT`
- 看到了 `demo:done`
