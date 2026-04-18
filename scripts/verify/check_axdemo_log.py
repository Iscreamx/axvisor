#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path


ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text).replace("\r", "")


def extract_marked_block(text: str, label: str) -> str:
    start = f"[[HOST-MARK]] BEGIN {label}\n"
    end = f"[[HOST-MARK]] END {label}\n"
    start_idx = text.find(start)
    end_idx = text.find(end, start_idx + len(start))
    if start_idx == -1 or end_idx == -1:
        raise RuntimeError(f"missing marked block: {label}")
    return text[start_idx + len(start):end_idx]


def require(text: str, pattern: str, description: str) -> None:
    if re.search(pattern, text, re.MULTILINE) is None:
        raise RuntimeError(f"missing evidence: {description}")


def parse_hprobe_rows(trace_list_block: str) -> dict[tuple[str, str], int]:
    rows: dict[tuple[str, str], int] = {}
    in_hprobes = False
    for line in trace_list_block.splitlines():
        if line.startswith("Hprobes (VMM probes):"):
            in_hprobes = True
            continue
        if in_hprobes and line.startswith("Guest Kprobes:"):
            break
        if not in_hprobes or not line.strip() or not line.startswith("  "):
            continue
        tokens = line.split()
        if len(tokens) < 6 or tokens[0] == "SYMBOL":
            continue
        symbol, _addr, hits, _prog_id, enabled, ret = tokens[:6]
        if enabled != "yes":
            continue
        rows[(symbol, ret)] = int(hits)
    return rows


def parse_guest_kprobe_rows(trace_list_block: str) -> dict[tuple[str, str], int]:
    rows: dict[tuple[str, str], int] = {}
    in_guest_kprobes = False
    for line in trace_list_block.splitlines():
        if line.startswith("Guest Kprobes:"):
            in_guest_kprobes = True
            continue
        if in_guest_kprobes and line.startswith("Guest Uprobes:"):
            break
        if not in_guest_kprobes or not line.strip() or not line.startswith("  vm"):
            continue
        tokens = line.split()
        if len(tokens) < 7 or tokens[0] == "VM":
            continue
        _vm, target, hits, _prog_id, _mode, ret, enabled = tokens[:7]
        if enabled != "yes":
            continue
        rows[(target, ret)] = int(hits)
    return rows


def parse_guest_uprobe_rows(trace_list_block: str) -> dict[tuple[str, str], tuple[str, int]]:
    rows: dict[tuple[str, str], tuple[str, int]] = {}
    in_guest_uprobes = False
    for line in trace_list_block.splitlines():
        if line.startswith("Guest Uprobes:"):
            in_guest_uprobes = True
            continue
        if not in_guest_uprobes or not line.strip() or not line.startswith("  vm"):
            continue
        tokens = line.split()
        if len(tokens) < 16 or tokens[0] == "VM":
            continue
        path = tokens[1]
        symbol = tokens[2]
        ret = tokens[12]
        state = tokens[13]
        hits = int(tokens[14])
        if path != "/usr/bin/axebpf_integration_demo":
            continue
        rows[(symbol, ret)] = (state, hits)
    return rows


def parse_trace_stat_count(trace_stat_block: str, event_name: str) -> int:
    for line in trace_stat_block.splitlines():
        if not line.startswith(event_name):
            continue
        tokens = line.split()
        if len(tokens) >= 2:
            return int(tokens[1])
    raise RuntimeError(f"missing trace stat row: {event_name}")


def parse_trace_stat_attachment_active(trace_stat_block: str, event_name: str) -> bool:
    for line in trace_stat_block.splitlines():
        tokens = line.split()
        if len(tokens) >= 4 and tokens[0] == event_name:
            return tokens[-1] == "active"
    return False


def parse_trace_stat_map_values(trace_stat_block: str, source_name: str) -> list[int]:
    values: list[int] = []
    for line in trace_stat_block.splitlines():
        tokens = line.split()
        if len(tokens) >= 4 and tokens[0] == source_name and tokens[1] == "COUNTER_MAP":
            values.append(int(tokens[-1]))
    return values


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} <raw-log>", file=sys.stderr)
        return 2

    log_path = Path(sys.argv[1])
    text = strip_ansi(log_path.read_text(encoding="utf-8", errors="ignore"))

    require(text, r"axebpf_integration_demo wrapper: launch", "launcher output")
    require(text, r"demo:start", "demo start marker")
    require(text, r"demo:done", "demo done marker")
    require(text, r"guest_uprobe_observer_exec: .*path=/usr/bin/axebpf_integration_demo", "guest exec observer")
    require(text, r"guest_uprobe_hit: .*path=/usr/bin/axebpf_integration_demo .*symbol=demo_user_entry", "uprobe hit")
    require(text, r"guest_uretprobe_hit: .*path=/usr/bin/axebpf_integration_demo .*symbol=demo_user_compute", "uretprobe hit")

    trace_list_block = extract_marked_block(text, "trace list (after demo done)")
    trace_stat_block = extract_marked_block(text, "trace stat (after demo done)")

    hprobe_rows = parse_hprobe_rows(trace_list_block)
    hprobe_entry_hit = max(
        (hits for (symbol, ret), hits in hprobe_rows.items() if symbol.endswith("notify_guest_vmexit") and ret == "no"),
        default=0,
    )
    hprobe_ret_hit = max(
        (hits for (symbol, ret), hits in hprobe_rows.items() if symbol.endswith("notify_guest_vmexit") and ret == "yes"),
        default=0,
    )
    if hprobe_entry_hit <= 0:
        raise RuntimeError("missing hprobe hits for notify_guest_vmexit")
    if hprobe_ret_hit <= 0:
        raise RuntimeError("missing hretprobe hits for notify_guest_vmexit")

    guest_kprobe_rows = parse_guest_kprobe_rows(trace_list_block)
    if guest_kprobe_rows.get(("gic_handle_irq+0x0", "no"), 0) <= 0:
        raise RuntimeError("missing guest-kprobe hits for gic_handle_irq")
    if guest_kprobe_rows.get(("__arm64_sys_getpid+0x0", "yes"), 0) <= 0:
        raise RuntimeError("missing guest-kretprobe hits for __arm64_sys_getpid")

    guest_uprobe_rows = parse_guest_uprobe_rows(trace_list_block)
    entry_state = guest_uprobe_rows.get(("demo_user_entry", "no"))
    compute_state = guest_uprobe_rows.get(("demo_user_compute", "yes"))
    if entry_state is None or entry_state[0] != "pending":
        raise RuntimeError("missing pending uprobe template for demo_user_entry")
    if compute_state is None or compute_state[0] != "pending":
        raise RuntimeError("missing pending uretprobe template for demo_user_compute")

    if not parse_trace_stat_attachment_active(trace_stat_block, "vmm:timer_tick"):
        raise RuntimeError("missing active tracepoint attachment for vmm:timer_tick")
    timer_tick_values = parse_trace_stat_map_values(trace_stat_block, "vmm:timer_tick")
    if not timer_tick_values or max(timer_tick_values) <= 0:
        raise RuntimeError("missing tracepoint map activity for vmm:timer_tick")

    print("PASS")
    print(f"  hprobe_entry={hprobe_entry_hit} hretprobe={hprobe_ret_hit}")
    print(f"  guest_kprobe_rows={guest_kprobe_rows}")
    print(f"  guest_uprobe_rows={guest_uprobe_rows}")
    print(f"  vmm:timer_tick_map_values={timer_tick_values}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
