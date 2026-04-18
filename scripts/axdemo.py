#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOGS_DIR = ROOT / "docs" / "ebpf-tracing" / "logs"
DEFAULT_WORK_ROOT = ROOT / "tmp" / "axebpf-mainline-oneclick"
DEFAULT_UPSTREAM_CACHE_ROOT = Path(tempfile.gettempdir()) / "axdemo-upstream-cache"
DEFAULT_AXVISOR_GUEST_REF = "v0.0.26"
DEFAULT_AXEBPF_PROGRAMS_URL = "https://github.com/Iscreamx/axebpf-programs.git"
AXVISOR_GUEST_RELEASE_IMAGE = "qemu_aarch64_linux.tar.gz"
REQUIRED_COMMANDS = (
    "git",
    "python3",
    "qemu-system-aarch64",
    "debugfs",
    "e2fsck",
    "fakeroot",
    "cpio",
    "gzip",
    "resize2fs",
    "aarch64-linux-gnu-gcc",
    "aarch64-linux-gnu-nm",
    "cargo",
    "llvm-nm",
)
REQUIRED_PYTHON_MODULES = ("pexpect",)
DEMO_GUEST_PATH = "/usr/bin/axebpf_integration_demo"
DEMO_GUEST_SYMS = "/vmimages/axebpf-integration-demo.syms"
GUEST_INIT_GUEST_PATH = "/init"
LAUNCHER_GUEST_PATH = "/etc/init.d/axebpf-integration-launch.sh"
INITTAB_GUEST_PATH = "/etc/inittab"
VMCONFIG_GUEST_PATH = "/vmconfigs/linux-qemu-smp1-axebpf-integration.toml"
LINUX_GUEST_BIN_PATH = "/vmimages/linux-qemu-aarch64.bin"
LINUX_GUEST_SYMS_PATH = "/vmimages/linux-qemu-aarch64.syms"
PRINTK_GUEST_PATH = "/vmimages/printk.o"
AXVISOR_ELF = ROOT / "target" / "aarch64-unknown-none-softfloat" / "release" / "axvisor"
AXVISOR_BIN = ROOT / "target" / "aarch64-unknown-none-softfloat" / "release" / "axvisor.bin"
CHECKER = ROOT / "scripts" / "verify" / "check_axdemo_log.py"
EMBEDDED_BUILD_CONFIG = """cargo_args = []
features = [
    "axstd/bus-mmio",
    "dyn-plat",
    "hprobe",
    "guest-kprobe",
    "guest-uprobe",
    "fs",
]
log = "Info"
target = "aarch64-unknown-none-softfloat"
to_bin = true
vm_configs = []
"""
EMBEDDED_DEMO_C = """typedef unsigned long u64;

#define AT_FDCWD (-100)
#define O_WRONLY 1
#define O_CREAT 0100
#define O_APPEND 02000
#define DEMO_LOOP_COUNT 3

struct timespec64 {
    long tv_sec;
    long tv_nsec;
};

static volatile u64 demo_state = 0x1234UL;

static long raw_syscall6(long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    register long x8 __asm__("x8") = nr;

    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
        : "cc", "memory");
    return x0;
}

static long sys_write(int fd, const char *buf, unsigned long len) {
    return raw_syscall6(64, fd, (long)buf, (long)len, 0, 0, 0);
}

static long sys_openat(int dirfd, const char *path, int flags, int mode) {
    return raw_syscall6(56, dirfd, (long)path, flags, mode, 0, 0);
}

static long sys_close(int fd) {
    return raw_syscall6(57, fd, 0, 0, 0, 0, 0);
}

static long sys_getpid(void) {
    return raw_syscall6(172, 0, 0, 0, 0, 0, 0);
}

static long sys_nanosleep(const struct timespec64 *req) {
    return raw_syscall6(101, (long)req, 0, 0, 0, 0, 0);
}

static void sys_exit(int code) {
    raw_syscall6(93, code, 0, 0, 0, 0, 0);
    for (;;) {
        __asm__ volatile("wfe");
    }
}

static unsigned long str_len(const char *s) {
    unsigned long len = 0;
    while (s[len] != '\\0') {
        len++;
    }
    return len;
}

static void write_line(const char *msg) {
    sys_write(1, msg, str_len(msg));
}

__attribute__((noinline)) u64 demo_user_entry(u64 tag, u64 iter) {
    demo_state ^= (tag << 8) + iter + 0x5a5aUL;
    return demo_state;
}

__attribute__((noinline)) long demo_user_compute(long base, long delta) {
    long result = base * 7 + delta + (long)(demo_state & 0xffUL);
    demo_state += (u64)result;
    return result;
}

static void run_phase_userspace(u64 iter) {
    u64 entry_value;
    long compute_value;

    write_line("phase1:userspace_fn begin\\n");
    entry_value = demo_user_entry(0x10 + iter, iter);
    compute_value = demo_user_compute((long)entry_value, (long)(iter + 3));
    if ((compute_value & 1L) == 0) {
        demo_state ^= (u64)compute_value;
    }
    write_line("phase1:userspace_fn end\\n");
}

static void run_phase_syscall(void) {
    long pid;

    write_line("phase2:syscall_io begin\\n");
    pid = sys_getpid();
    if (pid > 0) {
        demo_state ^= (u64)pid;
    }
    write_line("phase2:syscall_io end\\n");
}

static void run_phase_file_io(void) {
    static const char path[] = "/tmp/axebpf-demo.log";
    static const char payload[] = "axebpf-demo:file-io\\n";
    long fd;

    write_line("phase3:file_io begin\\n");
    fd = sys_openat(AT_FDCWD, path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        sys_write((int)fd, payload, sizeof(payload) - 1);
        sys_close((int)fd);
    }
    write_line("phase3:file_io end\\n");
}

static void run_demo(void) {
    struct timespec64 short_sleep = {
        .tv_sec = 0,
        .tv_nsec = 200000000,
    };
    struct timespec64 final_sleep = {
        .tv_sec = 1,
        .tv_nsec = 0,
    };
    u64 iter;

    write_line("demo:start\\n");
    write_line("phase4:repeat_window begin\\n");
    for (iter = 0; iter < DEMO_LOOP_COUNT; iter++) {
        run_phase_userspace(iter);
        run_phase_syscall();
        run_phase_file_io();
        sys_nanosleep(&short_sleep);
    }
    write_line("phase4:repeat_window end\\n");
    write_line("demo:done\\n");
    sys_nanosleep(&final_sleep);
}

void _start(void) {
    run_demo();
    sys_exit(0);
}
"""
EMBEDDED_DEMO_FALLBACK_ASM = """    .section .rodata
msg_demo_start:
    .asciz "demo:start\\n"
msg_repeat_begin:
    .asciz "phase4:repeat_window begin\\n"
msg_repeat_end:
    .asciz "phase4:repeat_window end\\n"
msg_demo_done:
    .asciz "demo:done\\n"
msg_phase1_begin:
    .asciz "phase1:userspace_fn begin\\n"
msg_phase1_end:
    .asciz "phase1:userspace_fn end\\n"
msg_phase2_begin:
    .asciz "phase2:syscall_io begin\\n"
msg_phase2_end:
    .asciz "phase2:syscall_io end\\n"
msg_phase3_begin:
    .asciz "phase3:file_io begin\\n"
msg_phase3_end:
    .asciz "phase3:file_io end\\n"
file_path:
    .asciz "/tmp/axebpf-demo.log"
file_payload:
    .asciz "axebpf-demo:file-io\\n"
short_sleep:
    .xword 0
    .xword 200000000
final_sleep:
    .xword 1
    .xword 0

    .section .data
    .align 3
demo_state:
    .xword 0x1234

    .section .text
    .align 2
    .global _start
    .global demo_user_entry
    .global demo_user_compute
"""
EMBEDDED_LAUNCHER_SH = """#!/bin/sh

echo "axebpf_integration_demo wrapper: launch" >/dev/console 2>&1
exec /usr/bin/axebpf_integration_demo >/dev/console 2>&1
"""
EMBEDDED_GUEST_INIT_SH = """#!/bin/sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin

if [ -x /bin/busybox ]; then
    /bin/busybox --install -s >/dev/null 2>&1
fi

TTY_DEV=/dev/console
[ -c /dev/ttyAMA0 ] && TTY_DEV=/dev/ttyAMA0
[ -c /dev/ttyS0 ] && TTY_DEV=/dev/ttyS0

/bin/busybox mkdir -p /proc /sys /dev /dev/pts /etc/init.d /tmp /vmimages
/bin/busybox mount -t proc proc /proc >/dev/null 2>&1
/bin/busybox mount -t sysfs sysfs /sys >/dev/null 2>&1
/bin/busybox mount -t devtmpfs devtmpfs /dev >/dev/null 2>&1 || true
/bin/busybox mount -t devpts devpts /dev/pts >/dev/null 2>&1 || true

/bin/sh /etc/init.d/axebpf-integration-launch.sh
echo "axebpf_integration_demo wrapper: idle" > "$TTY_DEV" 2>/dev/null || true

while true; do
    /bin/busybox sleep 3600
done
"""
EMBEDDED_INITTAB = "::sysinit:/bin/sh /etc/init.d/axebpf-integration-launch.sh\n"
EMBEDDED_VMCONFIG = """[base]
id = 1
name = "linux-qemu"
vm_type = 1
cpu_num = 1
cpu_ids = [1]

[kernel]
image_location = "fs"
kernel_path = "/vmimages/linux-qemu-aarch64.bin"
cmdline = "root=/dev/vda rw init=/init nokaslr"
memory_regions = [
  [0x8000_0000, 0x1000_0000, 0x7, 1],
]

[devices]
passthrough_devices = [
    ["/"],
]

passthrough_addresses = []

excluded_devices = []

emu_devices = []

interrupt_mode = "passthrough"
"""
EMBEDDED_KALLSYMS_DUMP_INIT = """#!/bin/sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin

if [ -x /bin/busybox ]; then
    /bin/busybox --install -s >/dev/null 2>&1
fi

TTY_DEV=/dev/console
[ -c /dev/ttyAMA0 ] && TTY_DEV=/dev/ttyAMA0
[ -c /dev/ttyS0 ] && TTY_DEV=/dev/ttyS0

/bin/busybox mkdir -p /proc /sys /dev /dev/pts /etc/init.d /vmimages
/bin/busybox mount -t proc proc /proc >/dev/null 2>&1
/bin/busybox mount -t sysfs sysfs /sys >/dev/null 2>&1
/bin/busybox mount -t devtmpfs devtmpfs /dev >/dev/null 2>&1 || true
/bin/busybox mount -t devpts devpts /dev/pts >/dev/null 2>&1 || true

if /bin/busybox grep ' [Tt] ' /proc/kallsyms > /vmimages/linux-qemu-aarch64.syms; then
    /bin/busybox sync
    echo "kallsyms dump pass!" > "$TTY_DEV" 2>/dev/null || echo "kallsyms dump pass!"
else
    echo "kallsyms dump failed!" > "$TTY_DEV" 2>/dev/null || echo "kallsyms dump failed!"
fi

while true; do
    /bin/busybox sleep 3600
done
"""
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
PROMPT = re.compile(r"axvisor:(?:/)?\$ ?")
PROMPT_LINE_RE = re.compile(r"^axvisor:(?:/)?\$ ?.*$")
VERBOSE_DISABLED = re.compile(r"Verbose mode: disabled")
EBPF_VERBOSE_DISABLED = re.compile(r"eBPF verbose mode: disabled")
TRACE_LIST_TOTAL = re.compile(r"Total:\s+\d+\s+tracepoints")
TRACE_STAT_HEADER = re.compile(r"PROBE STATISTICS:")
DEMO_WRAPPER = re.compile(r"axebpf_integration_demo wrapper: launch")
DEMO_START = re.compile(r"demo:start")
DEMO_DONE = re.compile(r"demo:done")
GUEST_KERNEL_PANIC = re.compile(r"Kernel panic - not syncing:")
UPROBE_EXEC = re.compile(r"guest_uprobe_observer_exec: .*path=/usr/bin/axebpf_integration_demo")
UPROBE_HIT = re.compile(r"guest_uprobe_hit: .*path=/usr/bin/axebpf_integration_demo .*symbol=demo_user_entry")
URETPROBE_ARM = re.compile(r"guest_uretprobe_arm: .*path=/usr/bin/axebpf_integration_demo .*symbol=demo_user_compute")
URETPROBE_HIT = re.compile(r"guest_uretprobe_hit: .*path=/usr/bin/axebpf_integration_demo .*symbol=demo_user_compute")
UPROBE_EXIT_MMAP = re.compile(r"guest_uprobe_observer_exit_mmap:")
UPROBE_DEACTIVATE_MM = re.compile(r"guest_uprobe_deactivate_mm:")
KPROBE_HITS = re.compile(r"guest_kprobe_hits:")
HPROBE_SAMPLE = re.compile(r"\[hprobe\].*sampled=true")
ROOTFS_EXPANDED_SIZE_MB = 256
LINUX_SYMS_RELEASE_CANDIDATES = ("linux.syms", "linux-qemu-aarch64.syms", "linux-mini.syms")


def make_run_layout(run_id: str) -> dict[str, Path]:
    log_dir = DEFAULT_LOGS_DIR / run_id
    return {
        "log_dir": log_dir,
        "raw_log": log_dir / "axebpf-mainline-integration.raw.log",
        "clean_log": log_dir / "axebpf-mainline-integration.clean.log",
        "summary": log_dir / "summary.txt",
    }


def prepare_run_layout(run_id: str, logs_dir: Path, work_root: Path) -> dict[str, Path]:
    log_dir = logs_dir / run_id
    work_dir = work_root / run_id
    log_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)
    return {
        "log_dir": log_dir,
        "raw_log": log_dir / "axebpf-mainline-integration.raw.log",
        "clean_log": log_dir / "axebpf-mainline-integration.clean.log",
        "summary": log_dir / "summary.txt",
        "work_dir": work_dir,
    }


def append_summary(summary_path: Path, stage: str, status: str, detail: str = "") -> None:
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    line = f"[{stage}] {status}"
    if detail:
        line = f"{line} {detail}"
    with summary_path.open("a", encoding="utf-8") as summary_file:
        summary_file.write(f"{line}\n")


def cleanup_workdir(work_dir: Path, *, keep_workdir: bool) -> None:
    if keep_workdir or not work_dir.exists():
        return
    shutil.rmtree(work_dir)


def plan_axvisor_guest_paths(work_root: Path, ref: str = DEFAULT_AXVISOR_GUEST_REF) -> dict[str, Path]:
    cache_root = work_root / "cache"
    downloads_dir = cache_root / "downloads"
    release_dir = cache_root / "release"
    archive_path = downloads_dir / f"qemu_aarch64_linux-{ref}.tar.gz"
    extract_dir = release_dir / f"qemu_aarch64_linux-{ref}"
    return {
        "cache_root": cache_root,
        "downloads_dir": downloads_dir,
        "release_dir": release_dir,
        "archive_path": archive_path,
        "extract_dir": extract_dir,
    }


def plan_axebpf_programs_paths(work_root: Path) -> dict[str, Path]:
    cache_root = DEFAULT_UPSTREAM_CACHE_ROOT
    clone_dir = cache_root / "axebpf-programs"
    output_dir = clone_dir / "output"
    return {
        "cache_root": cache_root,
        "clone_dir": clone_dir,
        "output_dir": output_dir,
    }


def build_axvisor_guest_release_url(ref: str) -> str:
    return (
        f"https://github.com/arceos-hypervisor/axvisor-guest/releases/download/"
        f"{ref}/{AXVISOR_GUEST_RELEASE_IMAGE}"
    )


def write_embedded_assets(staging_dir: Path) -> dict[str, Path]:
    staging_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "build_config": staging_dir / ".build.toml",
        "demo_c": staging_dir / "axebpf_integration_demo.c",
        "demo_fallback_asm": staging_dir / "axebpf_integration_demo_fallback.S",
        "guest_init": staging_dir / "axebpf-integration-guest-init.sh",
        "launcher": staging_dir / "axebpf-integration-launch.sh",
        "inittab": staging_dir / "axebpf-integration.inittab",
        "vmconfig": staging_dir / "linux-qemu-smp1-axebpf-integration.toml",
    }
    paths["build_config"].write_text(EMBEDDED_BUILD_CONFIG, encoding="utf-8")
    paths["demo_c"].write_text(EMBEDDED_DEMO_C, encoding="utf-8")
    paths["demo_fallback_asm"].write_text(EMBEDDED_DEMO_FALLBACK_ASM, encoding="utf-8")
    paths["guest_init"].write_text(EMBEDDED_GUEST_INIT_SH, encoding="utf-8")
    paths["launcher"].write_text(EMBEDDED_LAUNCHER_SH, encoding="utf-8")
    paths["inittab"].write_text(EMBEDDED_INITTAB, encoding="utf-8")
    paths["vmconfig"].write_text(EMBEDDED_VMCONFIG, encoding="utf-8")
    return paths


def clean_log_path(raw_path: Path) -> Path:
    name = raw_path.name
    if name.endswith(".raw.log"):
        return raw_path.with_name(name[: -len(".raw.log")] + ".clean.log")
    return raw_path.with_name(name + ".clean.log")


def collapse_prompt_redraws(lines: list[str]) -> str:
    collapsed: list[str] = []
    pending_prompt: str | None = None

    for line in lines:
        if PROMPT_LINE_RE.match(line):
            pending_prompt = line
            continue
        if pending_prompt is not None:
            collapsed.append(pending_prompt)
            pending_prompt = None
        collapsed.append(line)

    if pending_prompt is not None:
        collapsed.append(pending_prompt)

    return "\n".join(collapsed) + "\n"


def render_terminal_text(raw_text: str) -> str:
    rendered_lines: list[str] = []
    line: list[str] = []
    cursor = 0
    index = 0

    while index < len(raw_text):
        char = raw_text[index]
        if char == "\x1b":
            match = ANSI_RE.match(raw_text, index)
            if match is not None:
                sequence = match.group(0)
                if sequence.endswith("K"):
                    params = sequence[2:-1]
                    if params in ("", "0"):
                        del line[cursor:]
                    elif params == "1":
                        for pos in range(min(cursor, len(line))):
                            line[pos] = " "
                    elif params == "2":
                        line = []
                        cursor = 0
                index = match.end()
                continue
        if char == "\r":
            cursor = 0
            index += 1
            continue
        if char == "\n":
            rendered_lines.append("".join(line).rstrip())
            line = []
            cursor = 0
            index += 1
            continue
        if char == "\b":
            cursor = max(cursor - 1, 0)
            index += 1
            continue
        if cursor == len(line):
            line.append(char)
        elif cursor < len(line):
            line[cursor] = char
        else:
            line.extend(" " * (cursor - len(line)))
            line.append(char)
        cursor += 1
        index += 1

    if line:
        rendered_lines.append("".join(line).rstrip())

    return collapse_prompt_redraws(rendered_lines)


def write_clean_log(raw_path: Path) -> Path:
    clean_path = clean_log_path(raw_path)
    rendered = render_terminal_text(raw_path.read_text(encoding="utf-8", errors="ignore"))
    clean_path.write_text(rendered, encoding="utf-8")
    return clean_path


def check_command_output(command: str, output: str) -> None:
    if "Error:" in output or "Failed to" in output or "✗ " in output:
        raise RuntimeError(f"command failed: {command}\n{output}")


def send_trace_verbose_off(
    child,
    *,
    timeout: int = 120,
    log_file=None,
) -> str:
    if log_file is not None:
        log_file.write("\n[[HOST-MARK]] BEGIN trace verbose off\n")
        log_file.flush()
    child.sendline("trace verbose off")
    child.expect([VERBOSE_DISABLED, EBPF_VERBOSE_DISABLED], timeout=timeout)
    output = child.before or ""
    child.expect(PROMPT, timeout=timeout)
    if log_file is not None:
        log_file.write("\n[[HOST-MARK]] END trace verbose off\n")
        log_file.flush()
    output_text = output if isinstance(output, str) else str(output)
    check_command_output("trace verbose off", output_text)
    return output_text


def build_demo_compile_commands(
    assets: dict[str, Path],
    demo_bin: Path,
    demo_syms: Path,
    *,
    prefer_gcc: bool,
) -> list[list[str]]:
    if prefer_gcc:
        return [
            [
                "aarch64-linux-gnu-gcc",
                "-nostdlib",
                "-static",
                "-ffreestanding",
                "-fno-stack-protector",
                "-fomit-frame-pointer",
                "-O2",
                "-Wl,-e,_start",
                "-Wl,--build-id=none",
                str(assets["demo_c"]),
                "-o",
                str(demo_bin),
            ],
            ["aarch64-linux-gnu-nm", "-n", str(demo_bin)],
        ]
    obj_path = demo_bin.with_suffix(".o")
    return [
        [
            "llvm-mc",
            "-triple=aarch64-linux-gnu",
            "-filetype=obj",
            str(assets["demo_fallback_asm"]),
            "-o",
            str(obj_path),
        ],
        [
            "rust-lld",
            "-flavor",
            "gnu",
            "-m",
            "aarch64linux",
            "-e",
            "_start",
            str(obj_path),
            "-o",
            str(demo_bin),
        ],
        ["llvm-nm", "-n", str(demo_bin)],
    ]


def build_rootfs_injection_plan(
    rootfs_image: Path,
    demo_bin: Path,
    demo_syms: Path,
    assets: dict[str, Path],
) -> list[list[str]]:
    files = [
        (demo_bin, DEMO_GUEST_PATH, "0100755"),
        (demo_syms, DEMO_GUEST_SYMS, "0100644"),
        (assets["guest_init"], GUEST_INIT_GUEST_PATH, "0100755"),
        (assets["launcher"], LAUNCHER_GUEST_PATH, "0100755"),
        (assets["inittab"], INITTAB_GUEST_PATH, "0100644"),
        (assets["vmconfig"], VMCONFIG_GUEST_PATH, "0100644"),
    ]
    commands: list[list[str]] = []
    for source, target, mode in files:
        commands.append(["debugfs", "-w", "-R", f"rm {target}", str(rootfs_image)])
        commands.append(["debugfs", "-w", "-R", f"write {source} {target}", str(rootfs_image)])
        commands.append(["debugfs", "-w", "-R", f"set_inode_field {target} mode {mode}", str(rootfs_image)])
    return commands


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build the Linux base image and run the axebpf mainline integration flow.",
    )
    parser.add_argument(
        "--skip-build-axvisor",
        action="store_true",
        help="Reuse the existing axvisor build artifacts.",
    )
    parser.add_argument(
        "--keep-workdir",
        action="store_true",
        help="Keep the temporary work directory after the run finishes.",
    )
    parser.add_argument(
        "--axvisor-guest-ref",
        default=DEFAULT_AXVISOR_GUEST_REF,
        help="Git ref used for the axvisor-guest upstream checkout.",
    )
    parser.add_argument(
        "--logs-dir",
        type=Path,
        default=DEFAULT_LOGS_DIR,
        help="Directory used to store the final logs.",
    )
    parser.add_argument(
        "--reuse-axvisor-guest-clone",
        action="store_true",
        help="Reuse the cached axvisor-guest clone if it already exists.",
    )
    return parser.parse_args(argv)


def _default_import_checker(module_name: str) -> bool:
    return importlib.util.find_spec(module_name) is not None


def collect_missing_requirements(
    *,
    which=shutil.which,
    import_checker=_default_import_checker,
) -> list[str]:
    missing: list[str] = []

    for command in REQUIRED_COMMANDS:
        if which(command) is None:
            missing.append(command)
    for module_name in REQUIRED_PYTHON_MODULES:
        if not import_checker(module_name):
            missing.append(module_name)

    return missing


def run(cmd: list[str], *, cwd: Path | None = None, capture_output: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        check=True,
        text=True,
        cwd=str(cwd) if cwd is not None else None,
        stdout=subprocess.PIPE if capture_output else None,
        stderr=subprocess.PIPE if capture_output else None,
    )


def require_environment() -> None:
    missing = collect_missing_requirements()
    if missing:
        raise RuntimeError(f"missing requirements: {', '.join(missing)}")


def log_marker(log_file, label: str) -> None:
    log_file.write(f"\n[[HOST-MARK]] {label}\n")
    log_file.flush()


def send_and_wait(
    child,
    command: str,
    *,
    timeout: int = 120,
    log_file=None,
    label: str | None = None,
) -> str:
    marker = label if label is not None else command
    if log_file is not None:
        log_marker(log_file, f"BEGIN {marker}")
    child.sendline(command)
    child.expect(PROMPT, timeout=timeout)
    output = child.before or ""
    if log_file is not None:
        log_marker(log_file, f"END {marker}")
    output_text = output if isinstance(output, str) else str(output)
    check_command_output(command, output_text)
    return output_text


def send_trace_list(
    child,
    *,
    timeout: int = 120,
    log_file=None,
    label: str,
) -> str:
    if log_file is not None:
        log_marker(log_file, f"BEGIN {label}")
    child.sendline("trace list")
    child.expect(TRACE_LIST_TOTAL, timeout=timeout)
    total = child.after or ""
    child.expect(PROMPT, timeout=timeout)
    body = child.before or ""
    if log_file is not None:
        log_marker(log_file, f"END {label}")
    total_text = total if isinstance(total, str) else str(total)
    body_text = body if isinstance(body, str) else str(body)
    return f"{total_text}{body_text}"


def send_trace_stat(
    child,
    *,
    timeout: int = 120,
    log_file=None,
    label: str,
) -> str:
    if log_file is not None:
        log_marker(log_file, f"BEGIN {label}")
    child.sendline("trace stat")
    child.expect(TRACE_STAT_HEADER, timeout=timeout)
    header = child.after or ""
    child.expect(PROMPT, timeout=timeout)
    body = child.before or ""
    if log_file is not None:
        log_marker(log_file, f"END {label}")
    header_text = header if isinstance(header, str) else str(header)
    body_text = body if isinstance(body, str) else str(body)
    return f"{header_text}{body_text}"


def _pexpect_module():
    import pexpect

    return pexpect


def wait_for_post_demo_quiesce(child, *, quiet_timeout: int = 2) -> None:
    pexpect = _pexpect_module()
    while True:
        index = child.expect(
            [
                UPROBE_EXIT_MMAP,
                UPROBE_DEACTIVATE_MM,
                KPROBE_HITS,
                HPROBE_SAMPLE,
                PROMPT,
                pexpect.TIMEOUT,
            ],
            timeout=quiet_timeout,
        )
        if index in (4, 5):
            return


def wait_for_host_prompt(child, *, timeout: int = 5, retries: int = 3) -> None:
    pexpect = _pexpect_module()
    for attempt in range(retries + 1):
        index = child.expect(
            [
                PROMPT,
                UPROBE_EXIT_MMAP,
                UPROBE_DEACTIVATE_MM,
                KPROBE_HITS,
                HPROBE_SAMPLE,
                pexpect.TIMEOUT,
            ],
            timeout=timeout,
        )
        if index == 0:
            return
        if index == 5:
            if attempt == retries:
                raise RuntimeError("host shell prompt did not return after demo completion")
            child.sendline("")


def ensure_pending_uprobes(trace_list_output: str) -> None:
    for token in ("demo_user_entry", "demo_user_compute", "waiting-for-instance"):
        if token not in trace_list_output:
            raise RuntimeError(f"missing pending token in prestart trace list: {token}")


def _download_file(url: str, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=120) as response, output_path.open("wb") as output_file:
        shutil.copyfileobj(response, output_file)


def _find_release_asset(extract_dir: Path, filename: str) -> Path | None:
    matches = sorted(extract_dir.rglob(filename))
    if not matches:
        return None
    return matches[0]


def download_axvisor_guest_release(
    paths: dict[str, Path],
    ref: str,
    *,
    reuse_clone: bool,
) -> dict[str, Path]:
    archive_path = paths["archive_path"]
    extract_dir = paths["extract_dir"]

    if archive_path.exists() and not reuse_clone:
        archive_path.unlink()
    if not archive_path.exists():
        _download_file(build_axvisor_guest_release_url(ref), archive_path)

    if extract_dir.exists() and not reuse_clone:
        shutil.rmtree(extract_dir)
    if not extract_dir.exists():
        extract_dir.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archive_path, "r:gz") as archive:
            archive.extractall(extract_dir)

    linux_image = _find_release_asset(extract_dir, "qemu-aarch64")
    rootfs_image = _find_release_asset(extract_dir, "rootfs.img")
    if linux_image is None:
        raise FileNotFoundError("qemu-aarch64 not found in extracted axvisor-guest release")
    if rootfs_image is None:
        raise FileNotFoundError("rootfs.img not found in extracted axvisor-guest release")

    linux_syms = None
    for candidate in LINUX_SYMS_RELEASE_CANDIDATES:
        linux_syms = _find_release_asset(extract_dir, candidate)
        if linux_syms is not None:
            break

    paths["linux_image"] = linux_image
    paths["rootfs_image"] = rootfs_image
    paths["linux_syms"] = linux_syms
    return paths


def fetch_axebpf_programs(
    paths: dict[str, Path],
    *,
    reuse_clone: bool,
) -> dict[str, Path]:
    clone_dir = paths["clone_dir"]
    if clone_dir.exists() and not reuse_clone:
        shutil.rmtree(clone_dir)
    if not clone_dir.exists():
        clone_dir.parent.mkdir(parents=True, exist_ok=True)
        run(
            [
                "git",
                "clone",
                "--recursive",
                "--depth",
                "1",
                DEFAULT_AXEBPF_PROGRAMS_URL,
                str(clone_dir),
            ],
            cwd=ROOT,
        )
    return paths


def _write_stdout_to_file(command: list[str], *, cwd: Path, output_path: Path) -> None:
    result = run(command, cwd=cwd, capture_output=True)
    output_path.write_text(result.stdout, encoding="utf-8")


def expand_rootfs_image(rootfs_image: Path, *, size_mb: int = ROOTFS_EXPANDED_SIZE_MB) -> None:
    run(["truncate", "-s", f"{size_mb}M", str(rootfs_image)], cwd=ROOT)
    fsck = subprocess.run(
        ["e2fsck", "-fy", str(rootfs_image)],
        check=False,
        text=True,
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if fsck.returncode not in (0, 1):
        raise RuntimeError(f"e2fsck failed for {rootfs_image} with exit code {fsck.returncode}")
    run(["resize2fs", str(rootfs_image)], cwd=ROOT)


def _write_file(path: Path, content: str, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if executable:
        path.chmod(0o755)


def _dump_guest_file(rootfs_image: Path, guest_path: str, host_path: Path) -> None:
    host_path.parent.mkdir(parents=True, exist_ok=True)
    run(["debugfs", "-R", f"dump {guest_path} {host_path}", str(rootfs_image)], cwd=ROOT)


def bootstrap_linux_guest_syms(
    linux_image: Path,
    source_rootfs: Path,
    output_syms: Path,
    work_dir: Path,
) -> Path:
    pexpect = _pexpect_module()
    bootstrap_rootfs = work_dir / "linux-kallsyms-bootstrap.img"
    bootstrap_init = work_dir / "linux-kallsyms-dump-init.sh"
    bootstrap_log = work_dir / "linux-kallsyms-bootstrap.log"

    shutil.copyfile(source_rootfs, bootstrap_rootfs)
    expand_rootfs_image(bootstrap_rootfs, size_mb=64)
    _write_file(bootstrap_init, EMBEDDED_KALLSYMS_DUMP_INIT, executable=True)
    _debugfs_write(bootstrap_rootfs, bootstrap_init, "/init", "0100755")

    qemu_cmd = [
        "qemu-system-aarch64",
        "-nographic",
        "-cpu",
        "cortex-a72",
        "-machine",
        "virt,gic-version=3",
        "-smp",
        "1",
        "-device",
        "virtio-blk-device,drive=disk0",
        "-drive",
        f"id=disk0,if=none,format=raw,file={bootstrap_rootfs}",
        "-append",
        "root=/dev/vda rw init=/init nokaslr console=ttyAMA0",
        "-m",
        "2g",
        "-kernel",
        str(linux_image),
    ]

    with bootstrap_log.open("w", encoding="utf-8", errors="ignore") as log_file:
        child = pexpect.spawn(
            qemu_cmd[0],
            qemu_cmd[1:],
            cwd=str(ROOT),
            encoding="utf-8",
            codec_errors="ignore",
            timeout=180,
        )
        child.logfile = log_file
        try:
            child.expect("kallsyms dump pass!", timeout=180)
        finally:
            try:
                child.terminate(force=True)
            except Exception:
                pass

    _dump_guest_file(bootstrap_rootfs, LINUX_GUEST_SYMS_PATH, output_syms)
    return output_syms


def prepare_linux_base_image(
    run_paths: dict[str, Path],
    release_paths: dict[str, Path],
) -> dict[str, Path]:
    linux_image = release_paths["linux_image"]
    rootfs_image = release_paths["rootfs_image"]
    linux_syms = release_paths["linux_syms"]
    if not linux_image.exists():
        raise FileNotFoundError(linux_image)
    if not rootfs_image.exists():
        raise FileNotFoundError(rootfs_image)
    if linux_syms is not None and not linux_syms.exists():
        raise FileNotFoundError(linux_syms)

    image_dir = run_paths["image_dir"]
    image_dir.mkdir(parents=True, exist_ok=True)
    guest_bin = image_dir / "linux-qemu-aarch64.bin"
    guest_syms = image_dir / "linux-qemu-aarch64.syms"
    run_rootfs = image_dir / "rootfs-linux-axebpf-mainline-integration.img"

    shutil.copyfile(linux_image, guest_bin)
    shutil.copyfile(rootfs_image, run_rootfs)
    expand_rootfs_image(run_rootfs)
    if linux_syms is not None and linux_syms.exists():
        shutil.copyfile(linux_syms, guest_syms)
    else:
        bootstrap_linux_guest_syms(linux_image, rootfs_image, guest_syms, run_paths["work_dir"])
    run_paths["linux_guest_bin"] = guest_bin
    run_paths["linux_guest_syms"] = guest_syms
    run_paths["run_rootfs_image"] = run_rootfs
    return {
        "linux_guest_bin": guest_bin,
        "linux_guest_syms": guest_syms,
        "run_rootfs_image": run_rootfs,
    }


def _workspace_build_config_path() -> Path:
    return ROOT / ".build.toml"


def build_axvisor(build_config_path: Path) -> None:
    workspace_config = _workspace_build_config_path()
    original_text: str | None = None
    if workspace_config.exists():
        original_text = workspace_config.read_text(encoding="utf-8")

    workspace_config.write_text(build_config_path.read_text(encoding="utf-8"), encoding="utf-8")
    try:
        run(["cargo", "xtask", "build"], cwd=ROOT)
    finally:
        if original_text is None:
            if workspace_config.exists():
                workspace_config.unlink()
        else:
            workspace_config.write_text(original_text, encoding="utf-8")


def build_demo_binary(
    assets: dict[str, Path],
    build_dir: Path,
) -> dict[str, Path]:
    build_dir.mkdir(parents=True, exist_ok=True)
    demo_bin = build_dir / "axebpf_integration_demo"
    demo_syms = build_dir / "axebpf-integration-demo.syms"
    prefer_gcc = shutil.which("aarch64-linux-gnu-gcc") is not None and shutil.which("aarch64-linux-gnu-nm") is not None
    commands = build_demo_compile_commands(assets, demo_bin, demo_syms, prefer_gcc=prefer_gcc)
    for command in commands[:-1]:
        run(command, cwd=build_dir)
    _write_stdout_to_file(commands[-1], cwd=build_dir, output_path=demo_syms)
    return {
        "demo_bin": demo_bin,
        "demo_syms": demo_syms,
    }


def build_axebpf_programs(repo_dir: Path, output_dir: Path) -> dict[str, Path]:
    run(["bash", "build.sh"], cwd=repo_dir)
    printk_host = output_dir / "printk.o"
    if not printk_host.exists():
        raise FileNotFoundError(printk_host)
    return {"printk_host": printk_host}


def _ensure_guest_dir(rootfs_image: Path, guest_dir: str) -> None:
    if guest_dir in ("/", ""):
        return
    parts = [part for part in guest_dir.split("/") if part]
    current = ""
    for part in parts:
        current = f"{current}/{part}"
        subprocess.run(
            ["debugfs", "-w", "-R", f"mkdir {current}", str(rootfs_image)],
            check=False,
            text=True,
            cwd=str(ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def _debugfs_write(rootfs_image: Path, source: Path, target: str, mode: str) -> None:
    parent = str(Path(target).parent)
    _ensure_guest_dir(rootfs_image, parent)
    subprocess.run(
        ["debugfs", "-w", "-R", f"rm {target}", str(rootfs_image)],
        check=False,
        text=True,
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    run(["debugfs", "-w", "-R", f"write {source} {target}", str(rootfs_image)], cwd=ROOT)
    run(["debugfs", "-w", "-R", f"set_inode_field {target} mode {mode}", str(rootfs_image)], cwd=ROOT)


def inject_rootfs_files(
    rootfs_image: Path,
    linux_guest_bin: Path,
    linux_guest_syms: Path,
    printk_host: Path,
    assets: dict[str, Path],
    demo_outputs: dict[str, Path],
) -> None:
    if not printk_host.exists():
        raise FileNotFoundError(printk_host)

    _debugfs_write(rootfs_image, linux_guest_bin, LINUX_GUEST_BIN_PATH, "0100644")
    _debugfs_write(rootfs_image, linux_guest_syms, LINUX_GUEST_SYMS_PATH, "0100644")
    _debugfs_write(rootfs_image, printk_host, PRINTK_GUEST_PATH, "0100644")

    for command in build_rootfs_injection_plan(
        rootfs_image,
        demo_outputs["demo_bin"],
        demo_outputs["demo_syms"],
        assets,
    ):
        if command[3].startswith("write "):
            target = command[3].split()[-1]
            _ensure_guest_dir(rootfs_image, str(Path(target).parent))
        if command[3].startswith("rm "):
            subprocess.run(command, check=False, text=True, cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            continue
        run(command, cwd=ROOT)


def _require_guest_path(rootfs_image: Path, guest_path: str) -> None:
    result = subprocess.run(
        ["debugfs", "-R", f"stat {guest_path}", str(rootfs_image)],
        check=False,
        text=True,
        capture_output=True,
        cwd=str(ROOT),
    )
    if "File not found by ext2_lookup" in result.stdout or "File not found by ext2_lookup" in result.stderr:
        raise FileNotFoundError(guest_path)


def verify_injected_rootfs(rootfs_image: Path) -> None:
    for guest_path in (
        DEMO_GUEST_PATH,
        DEMO_GUEST_SYMS,
        LAUNCHER_GUEST_PATH,
        INITTAB_GUEST_PATH,
        VMCONFIG_GUEST_PATH,
        LINUX_GUEST_BIN_PATH,
        LINUX_GUEST_SYMS_PATH,
        PRINTK_GUEST_PATH,
    ):
        _require_guest_path(rootfs_image, guest_path)


def find_notify_guest_vmexit_symbol() -> str:
    result = run(["llvm-nm", str(AXVISOR_ELF)], capture_output=True)
    for line in result.stdout.splitlines():
        if "notify_guest_vmexit" in line:
            return line.split()[-1]
    raise RuntimeError("notify_guest_vmexit symbol not found in axvisor ELF")


def run_checker(log_path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["python3", str(CHECKER), str(log_path)],
        text=True,
        capture_output=True,
        check=False,
        cwd=str(ROOT),
    )


def run_qemu_integration(run_paths: dict[str, Path]) -> None:
    pexpect = _pexpect_module()
    notify_symbol = find_notify_guest_vmexit_symbol()
    qemu_cmd = [
        "qemu-system-aarch64",
        "-nographic",
        "-cpu",
        "cortex-a72",
        "-machine",
        "virt,virtualization=on,gic-version=3",
        "-smp",
        "4",
        "-device",
        "virtio-blk-device,drive=disk0",
        "-drive",
        f"id=disk0,if=none,format=raw,file={run_paths['run_rootfs_image']}",
        "-append",
        "root=/dev/vda rw init=/init",
        "-m",
        "8g",
        "-kernel",
        str(AXVISOR_BIN),
    ]
    raw_log = run_paths["raw_log"]
    with raw_log.open("w", encoding="utf-8", errors="ignore") as log_file:
        stamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S%z")
        log_file.write(f'Script started on {stamp} [COMMAND="{" ".join(qemu_cmd)}" <not executed on terminal>]\n')
        log_file.flush()
        child = pexpect.spawn(
            qemu_cmd[0],
            qemu_cmd[1:],
            cwd=str(ROOT),
            encoding="utf-8",
            codec_errors="ignore",
            timeout=180,
        )
        child.logfile = log_file
        try:
            child.expect(PROMPT, timeout=180)
            send_and_wait(child, "trace verbose on", log_file=log_file)
            send_and_wait(child, f"vm create {VMCONFIG_GUEST_PATH}", log_file=log_file)
            send_and_wait(child, f"trace loadsyms vm1 {LINUX_GUEST_SYMS_PATH}", log_file=log_file)
            send_and_wait(child, f"trace uloadelf vm1 {DEMO_GUEST_PATH} {DEMO_GUEST_SYMS}", log_file=log_file)
            send_and_wait(child, f"trace load file {PRINTK_GUEST_PATH} shell:shell_command", log_file=log_file)
            send_and_wait(child, "trace enable vmm:timer_tick", log_file=log_file)
            send_and_wait(child, "trace load prog 0 vmm:timer_tick", log_file=log_file)
            send_and_wait(child, f"trace hprobe {notify_symbol} 0", log_file=log_file)
            send_and_wait(child, f"trace hretprobe {notify_symbol} 0", log_file=log_file)
            send_and_wait(child, "trace kprobe vm1:gic_handle_irq 0 --inject", log_file=log_file)
            send_and_wait(child, "trace kprobe vm1:__arm64_sys_getpid 0 --inject --ret", log_file=log_file)
            send_and_wait(child, f"trace uprobe vm1:{DEMO_GUEST_PATH}:demo_user_entry 0", log_file=log_file)
            send_and_wait(child, f"trace uprobe vm1:{DEMO_GUEST_PATH}:demo_user_compute 0 --ret", log_file=log_file)

            pending_output = send_trace_list(
                child,
                timeout=180,
                log_file=log_file,
                label="trace list (before vm start)",
            )
            ensure_pending_uprobes(pending_output)

            log_marker(log_file, "BEGIN vm start 1")
            child.sendline("vm start 1")
            index = child.expect([DEMO_WRAPPER, GUEST_KERNEL_PANIC], timeout=180)
            if index == 1:
                panic_text = child.after or "guest kernel panic"
                raise RuntimeError(f"guest boot failed: {panic_text}")
            child.expect(UPROBE_EXEC, timeout=180)
            child.expect(DEMO_START, timeout=180)
            child.expect(UPROBE_HIT, timeout=180)
            child.expect(URETPROBE_ARM, timeout=180)
            child.expect(URETPROBE_HIT, timeout=180)
            child.expect(DEMO_DONE, timeout=180)
            log_marker(log_file, "END vm start 1")

            wait_for_post_demo_quiesce(child)
            wait_for_host_prompt(child)
            send_trace_verbose_off(child, log_file=log_file)
            time.sleep(1.0)
            send_trace_list(
                child,
                timeout=180,
                log_file=log_file,
                label="trace list (after demo done)",
            )
            send_trace_stat(
                child,
                timeout=180,
                log_file=log_file,
                label="trace stat (after demo done)",
            )
            send_and_wait(child, f"trace unhprobe {notify_symbol}", timeout=180, log_file=log_file)
        finally:
            try:
                child.terminate(force=True)
            except Exception:
                pass
    run_paths["clean_log"] = write_clean_log(raw_log)


def _run_stage(summary_path: Path, stage: str, func, *args, **kwargs):
    append_summary(summary_path, stage, "start")
    try:
        result = func(*args, **kwargs)
    except Exception as exc:
        append_summary(summary_path, stage, "failed", str(exc))
        raise
    append_summary(summary_path, stage, "ok")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_paths = prepare_run_layout(run_id, args.logs_dir, DEFAULT_WORK_ROOT)
    run_paths["staging_dir"] = run_paths["work_dir"] / "staging"
    run_paths["build_dir"] = run_paths["work_dir"] / "build"
    run_paths["image_dir"] = run_paths["work_dir"] / "images"
    summary_path = run_paths["summary"]

    failure: BaseException | None = None
    try:
        _run_stage(summary_path, "check_environment", require_environment)
        axvisor_guest_paths = plan_axvisor_guest_paths(DEFAULT_WORK_ROOT, args.axvisor_guest_ref)
        axebpf_program_paths = plan_axebpf_programs_paths(DEFAULT_WORK_ROOT)
        _run_stage(
            summary_path,
            "download_axvisor_guest_release",
            download_axvisor_guest_release,
            axvisor_guest_paths,
            args.axvisor_guest_ref,
            reuse_clone=args.reuse_axvisor_guest_clone,
        )
        _run_stage(
            summary_path,
            "fetch_axebpf_programs",
            fetch_axebpf_programs,
            axebpf_program_paths,
            reuse_clone=args.reuse_axvisor_guest_clone,
        )
        _run_stage(summary_path, "prepare_linux_base_image", prepare_linux_base_image, run_paths, axvisor_guest_paths)
        assets = _run_stage(summary_path, "write_embedded_assets", write_embedded_assets, run_paths["staging_dir"])
        if not args.skip_build_axvisor:
            _run_stage(summary_path, "build_axvisor", build_axvisor, assets["build_config"])
        bpf_outputs = _run_stage(
            summary_path,
            "build_axebpf_programs",
            build_axebpf_programs,
            axebpf_program_paths["clone_dir"],
            axebpf_program_paths["output_dir"],
        )
        demo_outputs = _run_stage(summary_path, "build_demo_binary", build_demo_binary, assets, run_paths["build_dir"])
        _run_stage(
            summary_path,
            "inject_rootfs_files",
            inject_rootfs_files,
            run_paths["run_rootfs_image"],
            run_paths["linux_guest_bin"],
            run_paths["linux_guest_syms"],
            bpf_outputs["printk_host"],
            assets,
            demo_outputs,
        )
        _run_stage(summary_path, "verify_injected_rootfs", verify_injected_rootfs, run_paths["run_rootfs_image"])
        _run_stage(summary_path, "run_qemu_integration", run_qemu_integration, run_paths)
    except BaseException as exc:
        failure = exc
    finally:
        cleanup_workdir(run_paths["work_dir"], keep_workdir=args.keep_workdir)

    if failure is not None:
        if run_paths["raw_log"].exists():
            print(run_paths["raw_log"], file=sys.stderr)
        if run_paths["clean_log"].exists():
            print(run_paths["clean_log"], file=sys.stderr)
        raise failure

    result = run_checker(run_paths["raw_log"])
    append_summary(summary_path, "check_log", f"exit={result.returncode}")
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    print(run_paths["raw_log"])
    print(run_paths["clean_log"])
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
