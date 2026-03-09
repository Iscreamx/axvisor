//! Trace commands for eBPF tracepoint management.
//!
//! Commands for listing, enabling, disabling tracepoints and viewing statistics.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};

use axstd::println;

use super::super::parser::{CommandNode, FlagDef, OptionDef, ParsedCommand};

// ============================================================================
// Command Handlers
// ============================================================================

fn trace_help(_cmd: &ParsedCommand) {
    println!("TRACE - eBPF tracepoint management");
    println!();
    println!("Commands:");
    println!("  list                              List all available tracepoints");
    println!("  enable <tp> [--prog NAME]         Enable tracepoint, optionally attach program");
    println!("  disable <tp>                      Disable a tracepoint");
    println!("  stat [--hist EVENT] [--top N]    Show probe statistics");
    println!("  stream [--filter TYPE] [-n N]    Stream events in real-time");
    println!("  dump [--filter TYPE] [-n N]      Dump buffered events");
    println!("  verbose [on|off]                  Control real-time eBPF output");
    println!("  reset                             Reset all statistics");
    println!("  load file <path> <tp>             Load eBPF program from file and attach");
    println!("  load prog <id> <tp>               Attach loaded program to tracepoint");
    println!("  unload <tp>                       Detach program from tracepoint");
    println!("  progs                             List pre-compiled and loaded programs");
    println!("  hprobe <symbol> <prog_id>         Attach hprobe to VMM function");
    println!("  hretprobe <symbol> <prog_id>      Attach hretprobe to VMM function");
    println!("  unhprobe <symbol>                 Detach hprobe from VMM function");
    println!("  kprobe vm<id>:<addr|symbol> <prog> Attach kprobe to guest kernel function");
    println!("  unkprobe vm<id>:<addr|symbol>     Detach kprobe from guest kernel function");
    println!("  loadsyms vm<id> <path>            Load guest symbol file (nm/System.map)");
    println!("  gsym vm<id> <name|addr>           Query guest symbol by name/address");
    println!();
    println!("Pre-compiled programs:");
    println!("  stats    - Event counter with latency (COUNT/TOTAL/MIN/MAX)");
    println!("  printk   - Debug logger with count");
    println!();
    println!("Examples:");
    println!("  trace enable vmm:vcpu_run_enter");
    println!("  trace enable vmm:vcpu_run_exit --prog stats");
    println!("  trace enable shell:shell_command --prog printk");
    println!("  trace hprobe axvm::Vm::create 0");
    println!("  trace verbose on");
    println!("  trace progs");
    println!("  trace stat");
}

#[cfg(feature = "ebpf")]
fn trace_list(_cmd: &ParsedCommand) {
    use axebpf::tracepoint::TracepointManager;

    let mgr = match TracepointManager::try_global() {
        Some(m) => m,
        None => {
            println!("Error: Tracepoint subsystem not initialized");
            return;
        }
    };

    let tracepoints = mgr.list_tracepoints();

    if tracepoints.is_empty() {
        println!("No tracepoints registered.");
        return;
    }

    println!("{:<30} {:<10} {:<6}", "NAME", "STATUS", "ID");
    println!("{:-<30} {:-<10} {:-<6}", "", "", "");

    for tp in tracepoints {
        let status = if tp.enabled { "enabled" } else { "disabled" };
        println!("{:<30} {:<10} {:<6}", tp.name, status, tp.id);
    }

    println!();
    println!("Total: {} tracepoints", mgr.count());

    // Add hprobe listing
    #[cfg(feature = "hprobe")]
    {
        println!();
        println!("Hprobes (VMM probes):");
        let probes = axebpf::hprobe_manager::list_all();
        if probes.is_empty() {
            println!("  (none)");
        } else {
            println!("  {:<20} {:<18} {:>8} {:>8} {:>6} {:>6}",
                     "SYMBOL", "ADDRESS", "HITS", "PROG_ID", "ENABLED", "RET");
            for (name, addr, hits, enabled, is_ret, prog_id) in probes {
                let status = if enabled { "yes" } else { "no" };
                let kind = if is_ret { "yes" } else { "no" };
                println!(
                    "  {:<20} {:#018x} {:>8} {:>8} {:>6} {:>6}",
                    name, addr, hits, prog_id, status, kind
                );
            }
        }
    }

    // Add guest kprobe listing
    #[cfg(feature = "guest-kprobe")]
    {
        println!();
        println!("Guest Kprobes:");
        let probes = axebpf::probe::kprobe::manager::list_all();
        if probes.is_empty() {
            println!("  (none)");
        } else {
            println!("  {:<6} {:<30} {:>8} {:>8} {:<10} {:<6} {:>6}",
                     "VM", "TARGET", "HITS", "PROG_ID", "MODE", "RET", "ENABLED");
            for (vm_id, gva, sym, hits, enabled, is_ret, prog_id, mode) in probes {
                let status = if enabled { "yes" } else { "no" };
                let kind = if is_ret { "yes" } else { "no" };
                let mode_str = match mode {
                    axebpf::probe::kprobe::manager::KprobeMode::Stage2Fault => "s2fault",
                    axebpf::probe::kprobe::manager::KprobeMode::BrkInject => "brk",
                };
                let target = match sym {
                    Some(name) => alloc::format!("{}+0x0", name),
                    None => alloc::format!("{:#018x}", gva),
                };
                println!(
                    "  vm{:<3} {:<30} {:>8} {:>8} {:<10} {:<6} {:>6}",
                    vm_id, target, hits, prog_id, mode_str, kind, status
                );
            }
        }
    }
}

#[cfg(not(feature = "ebpf"))]
fn trace_list(_cmd: &ParsedCommand) {
    println!("Error: eBPF feature not enabled");
    println!("Rebuild with --features ebpf to enable tracing");
}

#[cfg(feature = "ebpf")]
fn trace_enable(cmd: &ParsedCommand) {
    use axebpf::tracepoint::TracepointManager;
    use axebpf::{attach, runtime, ProgramRegistry};

    let args = &cmd.positional_args;

    if args.is_empty() {
        println!("Error: No tracepoint specified");
        println!("Usage: trace enable <tracepoint> [--prog stats|printk]");
        println!("Example: trace enable vmm:vcpu_run_enter --prog stats");
        return;
    }

    let mgr = match TracepointManager::try_global() {
        Some(m) => m,
        None => {
            println!("Error: Tracepoint subsystem not initialized");
            return;
        }
    };

    let prog_name = cmd.options.get("prog").map(|s| s.as_str());

    let tp_names: alloc::vec::Vec<_> = args.iter()
        .filter(|a| !a.starts_with("--"))
        .collect();

    for tp_name in tp_names {
        match mgr.enable(tp_name) {
            Ok(()) => println!("Enabled: {}", tp_name),
            Err(e) => {
                println!("Failed to enable {}: {:?}", tp_name, e);
                continue;
            }
        }

        if let Some(prog) = prog_name {
            match ProgramRegistry::get(prog) {
                Some(precompiled) => {
                    match runtime::load_program(precompiled.bytecode, None) {
                        Ok(prog_id) => {
                            match attach::attach(tp_name, prog_id, prog) {
                                Ok(()) => println!("Attached: {} program", prog),
                                Err(e) => {
                                    println!("Failed to attach {}: {}", prog, e);
                                    let _ = runtime::unload_program(prog_id);
                                }
                            }
                        }
                        Err(e) => println!("Failed to load {}: {}", prog, e),
                    }
                }
                None => {
                    println!("Unknown program: {}", prog);
                    println!("Available: stats, printk");
                }
            }
        }
    }
}

#[cfg(not(feature = "ebpf"))]
fn trace_enable(_cmd: &ParsedCommand) {
    println!("Error: eBPF feature not enabled");
}

#[cfg(feature = "ebpf")]
fn trace_disable(cmd: &ParsedCommand) {
    use axebpf::tracepoint::TracepointManager;

    let args = &cmd.positional_args;

    if args.is_empty() {
        println!("Error: No tracepoint specified");
        println!("Usage: trace disable <tracepoint>");
        return;
    }

    let mgr = match TracepointManager::try_global() {
        Some(m) => m,
        None => {
            println!("Error: Tracepoint subsystem not initialized");
            return;
        }
    };

    for tp_name in args {
        match mgr.disable(tp_name) {
            Ok(()) => println!("Disabled: {}", tp_name),
            Err(e) => println!("Failed to disable {}: {:?}", tp_name, e),
        }
    }
}

#[cfg(not(feature = "ebpf"))]
fn trace_disable(_cmd: &ParsedCommand) {
    println!("Error: eBPF feature not enabled");
}

#[cfg(feature = "ebpf")]
fn trace_stream(cmd: &ParsedCommand) {
    use axebpf::event;

    let max_events = cmd
        .options
        .get("n")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);
    let filter = cmd.options.get("filter").cloned();

    println!("Streaming events... (press Enter or q to stop)");
    print_trace_header();

    let mut count = 0usize;

    'stream: while max_events == 0 || count < max_events {
        if let Some(c) = try_read_char() {
            if c == b'\r' || c == b'\n' || c == b'q' || c == b'Q' {
                break 'stream;
            }
        }

        let batch = if max_events > 0 {
            core::cmp::min(32, max_events.saturating_sub(count))
        } else {
            32
        };

        let events = event::consume_events(batch);
        if events.is_empty() {
            core::hint::spin_loop();
            continue;
        }

        for ev in &events {
            if !matches_filter(ev, &filter) {
                continue;
            }
            print_trace_event(ev);
            count += 1;

            if max_events > 0 && count >= max_events {
                break 'stream;
            }
        }
    }

    println!();
    if max_events > 0 && count >= max_events {
        println!("Reached limit of {} events.", max_events);
    } else {
        println!("Stream stopped. {} events displayed.", count);
    }
}

#[cfg(feature = "ebpf")]
fn try_read_char() -> Option<u8> {
    use std::io::Read;

    let mut buf = [0u8; 1];
    match std::io::stdin().read(&mut buf) {
        Ok(1) => Some(buf[0]),
        _ => None,
    }
}

#[cfg(not(feature = "ebpf"))]
fn trace_stream(_cmd: &ParsedCommand) {
    println!("Error: eBPF feature not enabled");
}

#[cfg(feature = "ebpf")]
fn trace_dump(cmd: &ParsedCommand) {
    use axebpf::event;

    let max_events = cmd
        .options
        .get("n")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);
    let filter = cmd.options.get("filter").cloned();

    let events = event::consume_events(if max_events > 0 { max_events } else { 4096 });
    if events.is_empty() {
        println!("(no events)");
        return;
    }

    print_trace_header();

    let mut displayed = 0usize;
    for ev in &events {
        if !matches_filter(ev, &filter) {
            continue;
        }
        print_trace_event(ev);
        displayed += 1;
    }

    println!();
    println!(
        "{} events displayed ({} consumed from buffer).",
        displayed,
        events.len()
    );
}

#[cfg(not(feature = "ebpf"))]
fn trace_dump(_cmd: &ParsedCommand) {
    println!("Error: eBPF feature not enabled");
}

#[cfg(feature = "ebpf")]
fn print_trace_header() {
    println!(
        "{:<15} {:<5} {:<12} {:<30} {}",
        "TIMESTAMP", "CPU", "TYPE", "EVENT", "DETAILS"
    );
    println!(
        "{:-<15} {:-<5} {:-<12} {:-<30} {:-<30}",
        "", "", "", "", ""
    );
}

#[cfg(feature = "ebpf")]
fn print_trace_event(ev: &axebpf::event::TraceEvent) {
    use axebpf::event;

    let secs = ev.timestamp_ns / 1_000_000_000;
    let usecs = (ev.timestamp_ns % 1_000_000_000) / 1_000;
    let event_name =
        event::get_event_name(ev.name_offset).unwrap_or_else(|| alloc::format!("id:{}", ev.event_id));

    let mut details = String::new();
    if ev.nr_args > 0 {
        details.push_str("args=[");
        for i in 0..(ev.nr_args.min(4) as usize) {
            if i > 0 {
                details.push_str(", ");
            }
            details.push_str(&alloc::format!("{:#x}", ev.args[i]));
        }
        details.push(']');
    }

    if ev.duration_ns > 0 {
        if !details.is_empty() {
            details.push(' ');
        }
        details.push_str(&alloc::format!("dur={}", format_duration(ev.duration_ns)));
    }

    if ev.vm_id > 0 {
        if !details.is_empty() {
            details.push(' ');
        }
        details.push_str(&alloc::format!("vm{}", ev.vm_id));
    }

    println!(
        "[{:>5}.{:06}] cpu{:<2} {:<12} {:<30} {}",
        secs,
        usecs,
        ev.cpu_id,
        ev.probe_type_str(),
        event_name,
        details
    );
}

#[cfg(feature = "ebpf")]
fn format_duration(ns: u64) -> String {
    if ns < 1_000 {
        return alloc::format!("{}ns", ns);
    }
    if ns < 1_000_000 {
        let whole = ns / 1_000;
        let frac = (ns % 1_000) / 100;
        return alloc::format!("{}.{}us", whole, frac);
    }
    if ns < 1_000_000_000 {
        let whole = ns / 1_000_000;
        let frac = (ns % 1_000_000) / 100_000;
        return alloc::format!("{}.{}ms", whole, frac);
    }
    let whole = ns / 1_000_000_000;
    let frac = (ns % 1_000_000_000) / 10_000_000;
    alloc::format!("{}.{}s", whole, frac)
}

#[cfg(feature = "ebpf")]
fn matches_filter(ev: &axebpf::event::TraceEvent, filter: &Option<String>) -> bool {
    let Some(filter) = filter else {
        return true;
    };

    match filter.as_str() {
        "hprobe" => {
            ev.probe_type == axebpf::event::PROBE_HPROBE
                || ev.probe_type == axebpf::event::PROBE_HRETPROBE
        }
        "kprobe" => {
            ev.probe_type == axebpf::event::PROBE_KPROBE
                || ev.probe_type == axebpf::event::PROBE_KRETPROBE
        }
        "tracepoint" => ev.probe_type == axebpf::event::PROBE_TRACEPOINT,
        f if f.starts_with("vm") => {
            if let Ok(vm_id) = f[2..].parse::<u16>() {
                ev.vm_id == vm_id
            } else {
                true
            }
        }
        _ => true,
    }
}
#[cfg(feature = "ebpf")]
fn trace_stat(cmd: &ParsedCommand) {
    use axebpf::{attach, event, maps, runtime};

    let hist_event = cmd.options.get("hist").cloned();
    let top_n = cmd
        .options
        .get("top")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);

    let mut stats = event::all_stats();

    if !stats.is_empty() {
        if top_n > 0 {
            stats.sort_by(|a, b| b.1.count.cmp(&a.1.count));
            stats.truncate(top_n);
            println!("TOP {} EVENTS (by count):", top_n);
        } else {
            println!("PROBE STATISTICS:");
        }

        println!(
            "{:<30} {:>10} {:>10} {:>10} {:>10} {:>10}",
            "EVENT", "COUNT", "MIN", "MAX", "AVG", "LAST_TS"
        );
        println!(
            "{:-<30} {:-<10} {:-<10} {:-<10} {:-<10} {:-<10}",
            "", "", "", "", "", ""
        );

        for (event_id, snap) in &stats {
            let name = event::event_name_for_id(*event_id)
                .unwrap_or_else(|| alloc::format!("id:{}", event_id));

            let min_str = if snap.duration_samples == 0 {
                "-".to_string()
            } else {
                format_duration(snap.duration_min)
            };
            let max_str = if snap.duration_samples == 0 {
                "-".to_string()
            } else {
                format_duration(snap.duration_max)
            };
            let avg_str = if snap.duration_samples == 0 {
                "-".to_string()
            } else {
                format_duration(snap.duration_avg)
            };

            println!(
                "{:<30} {:>10} {:>10} {:>10} {:>10} {:>10}",
                name, snap.count, min_str, max_str, avg_str, snap.last_ts,
            );
        }
        println!();
    }

    if let Some(ref hist_name) = hist_event {
        println!("LATENCY HISTOGRAM ({}):", hist_name);
        for (event_id, snap) in &stats {
            let name = event::event_name_for_id(*event_id)
                .unwrap_or_else(|| alloc::format!("id:{}", event_id));
            if !name.contains(hist_name) {
                continue;
            }
            if snap.histogram.total == 0 {
                println!("  {}: (no samples)", name);
                continue;
            }

            let max_count = snap.histogram.buckets.iter().copied().max().unwrap_or(1);
            println!("  {}", name);
            for (idx, count) in snap.histogram.buckets.iter().enumerate() {
                let bar_len = if max_count > 0 {
                    ((*count as usize) * 40) / (max_count as usize)
                } else {
                    0
                };
                let bar: String = core::iter::repeat('|').take(bar_len).collect();
                println!("    {} : {:>8}  {}", axebpf::tracepoints::BUCKET_LABELS[idx], count, bar);
            }
            println!(
                "    P50={} P90={} P99={}",
                format_duration(snap.histogram.p50_ns),
                format_duration(snap.histogram.p90_ns),
                format_duration(snap.histogram.p99_ns)
            );
            println!();
        }
    }

    let attachments = attach::list_attachments();

    #[cfg(feature = "hprobe")]
    let hprobes = axebpf::hprobe_manager::list_all();
    #[cfg(not(feature = "hprobe"))]
    let hprobes: alloc::vec::Vec<(String, usize, u64, bool, bool, u32)> = alloc::vec::Vec::new();

    if !attachments.is_empty() || !hprobes.is_empty() {
        println!("EBPF ATTACHMENTS:");
        if !attachments.is_empty() {
            println!(
                "  {:<30} {:>8} {:<12} {:>8}",
                "TRACEPOINT", "PROG_ID", "PROG_NAME", "STATUS"
            );
            for (tp_name, info) in &attachments {
                let status = if runtime::get_program(info.prog_id).is_some() {
                    "active"
                } else {
                    "invalid"
                };
                println!(
                    "  {:<30} {:>8} {:<12} {:>8}",
                    tp_name, info.prog_id, info.prog_name, status
                );
            }
        }
        if !hprobes.is_empty() {
            println!("  {:<30} {:>8} {:>10} {:>8}", "HPROBE", "PROG_ID", "HITS", "STATUS");
            for (name, _addr, hits, enabled, _is_ret, prog_id) in &hprobes {
                let status = if *enabled { "active" } else { "disabled" };
                println!("  {:<30} {:>8} {:>10} {:>8}", name, prog_id, hits, status);
            }
        }

        let mut total_entries = 0usize;
        for (tp_name, info) in &attachments {
            if let Some(map_fds) = runtime::get_program_map_fds(info.prog_id) {
                for (map_name, map_fd) in map_fds {
                    let entries = maps::iter_entries(map_fd);
                    for (key, value) in &entries {
                        if total_entries == 0 {
                            println!();
                            println!("  MAP DATA:");
                            println!(
                                "  {:<30} {:<16} {:>10} {:>12}",
                                "SOURCE", "MAP_NAME", "KEY", "VALUE"
                            );
                        }
                        let key_val = if key.len() >= 4 {
                            u32::from_le_bytes(key[..4].try_into().unwrap_or([0; 4]))
                        } else {
                            0
                        };
                        let value_val = if value.len() >= 8 {
                            u64::from_le_bytes(value[..8].try_into().unwrap_or([0; 8]))
                        } else if value.len() >= 4 {
                            u32::from_le_bytes(value[..4].try_into().unwrap_or([0; 4])) as u64
                        } else {
                            0
                        };
                        println!(
                            "  {:<30} {:<16} {:>10} {:>12}",
                            tp_name, map_name, key_val, value_val
                        );
                        total_entries += 1;
                    }
                }
            }
        }

        println!();
    }

    if stats.is_empty() && attachments.is_empty() && hprobes.is_empty() {
        println!("No active probes or attachments.");
        println!("Use 'trace enable', 'trace hprobe', or 'trace kprobe' to start tracing.");
    }
}

#[cfg(not(feature = "ebpf"))]
fn trace_stat(_cmd: &ParsedCommand) {
    println!("Error: eBPF feature not enabled");
}

#[cfg(feature = "ebpf")]
fn trace_reset(_cmd: &ParsedCommand) {
    println!("Statistics reset is not supported.");
    println!("Statistics are managed by eBPF programs in Maps.");
    println!("To reset, detach and re-attach the stats program.");
}

#[cfg(not(feature = "ebpf"))]
fn trace_reset(_cmd: &ParsedCommand) {
    println!("Error: eBPF feature not enabled");
}

#[cfg(feature = "ebpf")]
fn trace_load(cmd: &ParsedCommand) {
    let args = &cmd.positional_args;

    if args.len() < 2 {
        println!("Usage: trace load file <path> <tracepoint>");
        println!("       trace load prog <id> <tracepoint>");
        return;
    }

    let mode = &args[0];
    match mode.as_str() {
        "prog" => trace_load_prog(&args[1..]),
        "file" => trace_load_file(&args[1..]),
        _ => {
            println!("Unknown mode: {}", mode);
            println!("Usage: trace load file <path> <tracepoint>");
            println!("       trace load prog <id> <tracepoint>");
        }
    }
}

#[cfg(feature = "ebpf")]
fn trace_load_prog(args: &[String]) {
    use axebpf::{attach, runtime};

    if args.len() < 2 {
        println!("Usage: trace load prog <id> <tracepoint>");
        return;
    }

    let prog_id: u32 = match args[0].parse() {
        Ok(id) => id,
        Err(_) => {
            println!("Invalid program ID: {}", args[0]);
            return;
        }
    };

    let tracepoint = &args[1];

    if runtime::get_program(prog_id).is_none() {
        println!("Program {} not found", prog_id);
        return;
    }

    match attach::attach(tracepoint, prog_id, "custom") {
        Ok(()) => println!("Attached program {} to {}", prog_id, tracepoint),
        Err(e) => println!("Failed to attach: {}", e),
    }
}

#[cfg(not(feature = "ebpf"))]
fn trace_load(_cmd: &ParsedCommand) {
    println!("Error: eBPF feature not enabled");
}

#[cfg(all(feature = "ebpf", feature = "fs"))]
fn trace_load_file(args: &[String]) {
    use axebpf::{attach, runtime};
    use axstd::fs::File;
    use axstd::io::Read;

    if args.len() < 2 {
        println!("Usage: trace load file <path> <tracepoint>");
        return;
    }

    let path = &args[0];
    let tracepoint = &args[1];

    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            println!("Failed to open {}: {:?}", path, e);
            return;
        }
    };

    let file_size = match file.metadata() {
        Ok(meta) => meta.len() as usize,
        Err(e) => {
            println!("Failed to get file metadata: {:?}", e);
            return;
        }
    };

    if file_size == 0 {
        println!("Error: File {} is empty", path);
        return;
    }

    let mut bytecode = alloc::vec![0u8; file_size];
    let mut reader = axstd::io::BufReader::new(file);
    if let Err(e) = reader.read_exact(&mut bytecode) {
        println!("Failed to read {}: {:?}", path, e);
        return;
    }

    let prog_id = match runtime::load_program(&bytecode, None) {
        Ok(id) => id,
        Err(e) => {
            println!("Failed to load program: {}", e);
            return;
        }
    };

    println!("Loaded program {} ({} bytes) from {}", prog_id, bytecode.len(), path);

    match attach::attach(tracepoint, prog_id, "file") {
        Ok(()) => println!("Attached to {}", tracepoint),
        Err(e) => {
            println!("Failed to attach: {}", e);
            let _ = runtime::unload_program(prog_id);
        }
    }
}

#[cfg(all(feature = "ebpf", not(feature = "fs")))]
fn trace_load_file(_args: &[String]) {
    println!("Error: File system feature not enabled");
    println!("Use 'trace load prog <id> <tracepoint>' instead");
}

#[cfg(feature = "ebpf")]
fn trace_unload(cmd: &ParsedCommand) {
    use axebpf::attach;

    let args = &cmd.positional_args;

    if args.is_empty() {
        println!("Usage: trace unload <tracepoint>");
        return;
    }

    let tracepoint = &args[0];

    match attach::detach(tracepoint) {
        Ok(info) => println!("Detached program {} ({}) from {}", info.prog_name, info.prog_id, tracepoint),
        Err(e) => println!("Failed to detach: {}", e),
    }
}

#[cfg(not(feature = "ebpf"))]
fn trace_unload(_cmd: &ParsedCommand) {
    println!("Error: eBPF feature not enabled");
}

#[cfg(feature = "ebpf")]
fn trace_progs(_cmd: &ParsedCommand) {
    use axebpf::{attach, runtime, ProgramRegistry};

    println!("Pre-compiled programs:");
    let precompiled = ProgramRegistry::list();
    if precompiled.is_empty() {
        println!("  (none available - run 'cargo xtask build-ebpf')");
    } else {
        for prog in &precompiled {
            println!("  {:10} - {}", prog.name, prog.description);
        }
    }
    println!();

    let programs = runtime::list_programs();
    let attachments = attach::list_attachments();

    println!("Loaded programs:");
    if programs.is_empty() {
        println!("  (none)");
    } else {
        println!("{:<6} {:<10} {}", "ID", "SIZE", "ATTACHED TO");
        println!("{:-<6} {:-<10} {:-<30}", "", "", "");

        for prog in &programs {
            let attached: alloc::vec::Vec<_> = attachments
                .iter()
                .filter(|(_, info)| info.prog_id == prog.id)
                .map(|(tp, _)| tp.as_str())
                .collect();

            let attached_str = if attached.is_empty() {
                "-".to_string()
            } else {
                attached.join(", ")
            };

            println!("{:<6} {:<10} {}", prog.id, prog.size, attached_str);
        }
    }

    println!();
    println!("Total: {} loaded, {} attachments", programs.len(), attachments.len());
}

#[cfg(not(feature = "ebpf"))]
fn trace_progs(_cmd: &ParsedCommand) {
    println!("Error: eBPF feature not enabled");
}

#[cfg(feature = "ebpf")]
fn trace_verbose(cmd: &ParsedCommand) {
    use axebpf::attach;

    let args = &cmd.positional_args;

    if args.is_empty() {
        // Show current status
        let status = if attach::is_verbose() { "enabled" } else { "disabled" };
        println!("Verbose mode: {}", status);
        return;
    }

    match args[0].as_str() {
        "on" | "true" | "1" => {
            attach::set_verbose(true);
            println!("Verbose mode: enabled");
        }
        "off" | "false" | "0" => {
            attach::set_verbose(false);
            println!("Verbose mode: disabled");
        }
        _ => {
            println!("Usage: trace verbose [on|off]");
            println!("  on   - Enable real-time eBPF output");
            println!("  off  - Disable real-time eBPF output");
        }
    }
}

#[cfg(not(feature = "ebpf"))]
fn trace_verbose(_cmd: &ParsedCommand) {
    println!("Error: eBPF feature not enabled");
}

// ============================================================================
// Hprobe Command Handlers (VMM self-introspection)
// ============================================================================

/// Handle `trace hprobe <symbol> <prog_name_or_id>` command
#[cfg(feature = "hprobe")]
fn trace_hprobe(cmd: &ParsedCommand) {
    use axebpf::hprobe_manager;
    use axebpf::symbols;
    use axebpf::{runtime, ProgramRegistry};

    // Initialize hprobe subsystem if needed
    hprobe_manager::init();

    // Install exception vector table with BRK handler support
    axvm::install_trap_vector();

    let args = &cmd.positional_args;
    if args.len() < 2 {
        println!("Usage: trace hprobe <symbol> <prog_name_or_id>");
        println!("Example: trace hprobe _RNv...symbol_name kprobe_args");
        println!("         trace hprobe _RNv...symbol_name 0");
        return;
    }

    let symbol = &args[0];
    let prog_arg = &args[1];

    // Try to parse as prog_id first, otherwise treat as program name
    let prog_id: u32 = match prog_arg.parse() {
        Ok(id) => id,
        Err(_) => {
            // Treat as program name - load from precompiled
            match ProgramRegistry::get(prog_arg) {
                Some(precompiled) => {
                    match runtime::load_program(precompiled.bytecode, None) {
                        Ok(id) => {
                            println!("Loaded program '{}' with id {}", prog_arg, id);
                            id
                        }
                        Err(e) => {
                            println!("Failed to load program '{}': {}", prog_arg, e);
                            return;
                        }
                    }
                }
                None => {
                    println!("Unknown program: {}", prog_arg);
                    println!("Available programs:");
                    for prog in ProgramRegistry::list() {
                        println!("  {}", prog.name);
                    }
                    return;
                }
            }
        }
    };

    // Check if symbol table is initialized
    if !symbols::is_initialized() {
        println!("Error: Symbol table not initialized!");
        println!("This is a bug - symbol table should be loaded at boot.");
        return;
    }

    // Try to lookup the symbol first
    match symbols::lookup_addr(symbol) {
        Some(addr) => {
            println!("Symbol '{}' found at {:#x}", symbol, addr);
        }
        None => {
            println!("Symbol '{}' not found in symbol table", symbol);
            println!("Hint: Use 'ksym search <pattern>' to find the mangled name");
            return;
        }
    }

    match hprobe_manager::attach(symbol, prog_id, false) {
        Ok(addr) => {
            println!("Hprobe attached: {} @ {:#x} -> prog {}", symbol, addr, prog_id);
        }
        Err(e) => {
            println!("Failed to attach hprobe: {}", e);
        }
    }
}

#[cfg(not(feature = "hprobe"))]
fn trace_hprobe(_cmd: &ParsedCommand) {
    println!("Error: hprobe feature not enabled");
    println!("Rebuild with --features hprobe to enable VMM probe support");
}

/// Handle `trace hretprobe <symbol> <prog_name_or_id>` command
#[cfg(feature = "hprobe")]
fn trace_hretprobe(cmd: &ParsedCommand) {
    use axebpf::hprobe_manager;
    use axebpf::symbols;
    use axebpf::{runtime, ProgramRegistry};

    hprobe_manager::init();

    // Install exception vector table with BRK handler support
    axvm::install_trap_vector();

    let args = &cmd.positional_args;
    if args.len() < 2 {
        println!("Usage: trace hretprobe <symbol> <prog_name_or_id>");
        println!("Example: trace hretprobe _RNv...symbol_name stats");
        println!("         trace hretprobe _RNv...symbol_name 0");
        return;
    }

    let symbol = &args[0];
    let prog_arg = &args[1];

    // Try to parse as prog_id first, otherwise treat as program name
    let prog_id: u32 = match prog_arg.parse() {
        Ok(id) => id,
        Err(_) => {
            // Treat as program name - load from precompiled
            match ProgramRegistry::get(prog_arg) {
                Some(precompiled) => {
                    match runtime::load_program(precompiled.bytecode, None) {
                        Ok(id) => {
                            println!("Loaded program '{}' with id {}", prog_arg, id);
                            id
                        }
                        Err(e) => {
                            println!("Failed to load program '{}': {}", prog_arg, e);
                            return;
                        }
                    }
                }
                None => {
                    println!("Unknown program: {}", prog_arg);
                    println!("Available programs:");
                    for prog in ProgramRegistry::list() {
                        println!("  {}", prog.name);
                    }
                    return;
                }
            }
        }
    };

    // Check if symbol table is initialized
    if !symbols::is_initialized() {
        println!("Error: Symbol table not initialized!");
        println!("This is a bug - symbol table should be loaded at boot.");
        return;
    }

    // Try to lookup the symbol first
    match symbols::lookup_addr(symbol) {
        Some(addr) => {
            println!("Symbol '{}' found at {:#x}", symbol, addr);
        }
        None => {
            println!("Symbol '{}' not found in symbol table", symbol);
            println!("Hint: Use 'ksym search <pattern>' to find the mangled name");
            return;
        }
    }

    match hprobe_manager::attach(symbol, prog_id, true) {
        Ok(addr) => {
            println!("Hretprobe attached: {} @ {:#x} -> prog {}", symbol, addr, prog_id);
        }
        Err(e) => {
            println!("Failed to attach hretprobe: {}", e);
        }
    }
}

#[cfg(not(feature = "hprobe"))]
fn trace_hretprobe(_cmd: &ParsedCommand) {
    println!("Error: hprobe feature not enabled");
}

/// Handle `trace unhprobe <symbol>` command
#[cfg(feature = "hprobe")]
fn trace_unhprobe(cmd: &ParsedCommand) {
    use axebpf::hprobe_manager;

    let args = &cmd.positional_args;
    if args.is_empty() {
        println!("Usage: trace unhprobe <symbol_name>");
        return;
    }

    let symbol = &args[0];

    match hprobe_manager::detach(symbol) {
        Ok(()) => {
            println!("Hprobe detached: {}", symbol);
        }
        Err(e) => {
            println!("Failed to detach hprobe: {}", e);
        }
    }
}

#[cfg(not(feature = "hprobe"))]
fn trace_unhprobe(_cmd: &ParsedCommand) {
    println!("Error: hprobe feature not enabled");
}

// ============================================================================
// Guest Kprobe Command Handlers
// ============================================================================

/// Handle `trace kprobe vm<id>:<addr> <prog_name_or_id>` command
#[cfg(feature = "guest-kprobe")]
fn trace_kprobe(cmd: &ParsedCommand) {
    use axebpf::probe::kprobe::manager::{self as guest_kprobe, KprobeMode};
    use axebpf::{runtime, ProgramRegistry};

    guest_kprobe::init();

    let args = &cmd.positional_args;
    if args.len() < 2 {
        println!("Usage: trace kprobe vm<id>:<addr|symbol> <prog_name_or_id>");
        println!("Options: --inject (BRK injection mode), --ret (return probe)");
        println!("Example: trace kprobe vm0:0xffff800080012340 kprobe_args");
        return;
    }

    // Parse vm<id>:<addr> format
    let target = &args[0];
    let (vm_id, addr_str) = match parse_vm_target(target) {
        Some(v) => v,
        None => {
            println!("Error: invalid target format. Use vm<id>:<addr|symbol>");
            println!("Example: vm0:0xffff800080012340");
            return;
        }
    };

    let (gva, resolved_by_symbol) = match resolve_guest_gva(vm_id, addr_str) {
        Some(v) => v,
        None => return,
    };

    // Parse program argument
    let prog_arg = &args[1];
    let prog_id: u32 = match prog_arg.parse() {
        Ok(id) => id,
        Err(_) => {
            match ProgramRegistry::get(prog_arg) {
                Some(precompiled) => {
                    match runtime::load_program(precompiled.bytecode, None) {
                        Ok(id) => {
                            println!("Loaded program '{}' with id {}", prog_arg, id);
                            id
                        }
                        Err(e) => {
                            println!("Failed to load program '{}': {}", prog_arg, e);
                            return;
                        }
                    }
                }
                None => {
                    println!("Unknown program: {}", prog_arg);
                    return;
                }
            }
        }
    };

    let inject = cmd.flags.contains_key(&"inject".to_string());
    let is_ret = cmd.flags.contains_key(&"ret".to_string());
    let mode = if inject { KprobeMode::BrkInject } else { KprobeMode::Stage2Fault };

    match guest_kprobe::attach(vm_id, gva, prog_id, is_ret, mode) {
        Ok(()) => {
            if resolved_by_symbol {
                let _ = guest_kprobe::set_symbol(vm_id, gva, Some(addr_str));
            } else if let Some((name, _ty, offset)) = axebpf::guest_symbols::lookup_name(vm_id, gva) {
                if offset == 0 {
                    let _ = guest_kprobe::set_symbol(vm_id, gva, Some(&name));
                }
            }
            let mode_str = if inject { "brk-inject" } else { "s2fault" };
            let kind = if is_ret { "kretprobe" } else { "kprobe" };
            if guest_kprobe::lookup_enabled(vm_id, gva).is_some() {
                println!(
                    "{} attached: vm{}:{:#x} -> prog {} (mode={})",
                    kind, vm_id, gva, prog_id, mode_str
                );
            } else {
                println!(
                    "{} registered pending enable: vm{}:{:#x} -> prog {} (mode={})",
                    kind, vm_id, gva, prog_id, mode_str
                );
                println!("Hint: start the VM and wait for TTBR1_EL1 / first VM-exit.");
            }
        }
        Err(e) => {
            println!("Failed to attach kprobe: {}", e);
        }
    }
}

#[cfg(not(feature = "guest-kprobe"))]
fn trace_kprobe(_cmd: &ParsedCommand) {
    println!("Error: guest-kprobe feature not enabled");
    println!("Rebuild with --features guest-kprobe to enable guest kernel probing");
}

/// Handle `trace unkprobe vm<id>:<addr>` command
#[cfg(feature = "guest-kprobe")]
fn trace_unkprobe(cmd: &ParsedCommand) {
    use axebpf::probe::kprobe::manager as guest_kprobe;

    let args = &cmd.positional_args;
    if args.is_empty() {
        println!("Usage: trace unkprobe vm<id>:<addr>");
        return;
    }

    let target = &args[0];
    let (vm_id, addr_str) = match parse_vm_target(target) {
        Some(v) => v,
        None => {
            println!("Error: invalid target format. Use vm<id>:<addr|symbol>");
            return;
        }
    };

    let (gva, _) = match resolve_guest_gva(vm_id, addr_str) {
        Some(v) => v,
        None => return,
    };

    match guest_kprobe::detach(vm_id, gva) {
        Ok(()) => println!("kprobe detached: vm{}:{:#x}", vm_id, gva),
        Err(e) => println!("Failed to detach kprobe: {}", e),
    }
}

#[cfg(not(feature = "guest-kprobe"))]
fn trace_unkprobe(_cmd: &ParsedCommand) {
    println!("Error: guest-kprobe feature not enabled");
}

/// Handle `trace loadsyms vm<id> <path>` command.
#[cfg(all(feature = "guest-kprobe", feature = "fs"))]
fn trace_loadsyms(cmd: &ParsedCommand) {
    use axstd::fs::File;
    use axstd::io::Read;

    let args = &cmd.positional_args;
    if args.len() < 2 {
        println!("Usage: trace loadsyms vm<ID> <PATH>");
        println!("  Load an nm/System.map symbol file for a guest VM.");
        println!("Example: trace loadsyms vm0 /arceos.syms");
        return;
    }

    let vm_str = &args[0];
    let vm_id = match parse_vm_id(vm_str) {
        Some(id) => id,
        None => {
            println!("Error: invalid VM ID '{}'. Use vm<N> format.", vm_str);
            return;
        }
    };

    let path = &args[1];
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            println!("Error: failed to open '{}': {}", path, e);
            return;
        }
    };

    let mut content = String::new();
    if let Err(e) = file.read_to_string(&mut content) {
        println!("Error: failed to read '{}': {}", path, e);
        return;
    }

    match axebpf::guest_symbols::load_from_text(vm_id, &content) {
        Ok(count) => println!("Loaded {} symbols for vm{} from '{}'", count, vm_id, path),
        Err(e) => println!("Error: failed to parse symbols: {}", e),
    }
}

#[cfg(all(feature = "guest-kprobe", not(feature = "fs")))]
fn trace_loadsyms(_cmd: &ParsedCommand) {
    println!("Error: file system feature not enabled");
    println!("Rebuild with --features fs to load symbols from files");
}

#[cfg(not(feature = "guest-kprobe"))]
fn trace_loadsyms(_cmd: &ParsedCommand) {
    println!("Error: guest-kprobe feature not enabled");
}

/// Handle `trace gsym vm<id> <name|addr|search pattern>` command.
#[cfg(feature = "guest-kprobe")]
fn trace_gsym(cmd: &ParsedCommand) {
    let args = &cmd.positional_args;
    if args.len() < 2 {
        println!("Usage: trace gsym vm<ID> <NAME|ADDR>");
        println!("       trace gsym vm<ID> search <PATTERN>");
        println!("Example: trace gsym vm0 main");
        println!("         trace gsym vm0 0xffff800080001000");
        return;
    }

    let vm_str = &args[0];
    let vm_id = match parse_vm_id(vm_str) {
        Some(id) => id,
        None => {
            println!("Error: invalid VM ID '{}'. Use vm<N> format.", vm_str);
            return;
        }
    };

    if !axebpf::guest_symbols::is_loaded(vm_id) {
        println!("No symbols loaded for vm{}.", vm_id);
        println!("Hint: use 'trace loadsyms vm{} <path>' first.", vm_id);
        return;
    }

    if args[1] == "search" {
        if args.len() < 3 {
            println!("Usage: trace gsym vm<ID> search <PATTERN>");
            return;
        }

        let pattern = &args[2];
        let results = axebpf::guest_symbols::search(vm_id, pattern, 20);
        if results.is_empty() {
            println!("No symbols matching '{}' in vm{}", pattern, vm_id);
        } else {
            println!("{} result(s) for '{}' in vm{}:", results.len(), pattern, vm_id);
            for (addr, name, ty) in &results {
                println!("  {:#018x} {} {}", addr, ty, name);
            }
        }
        return;
    }

    let query = &args[1];
    if query.starts_with("0x") || query.starts_with("0X") {
        let Some(addr) = parse_hex_u64(query) else {
            println!("Error: invalid hex address '{}'", query);
            return;
        };
        match axebpf::guest_symbols::lookup_name(vm_id, addr) {
            Some((name, ty, offset)) if offset == 0 => {
                println!("{:#018x} {} {}", addr, ty, name);
            }
            Some((name, ty, offset)) => {
                println!("{:#018x} {} {}+{:#x}", addr, ty, name, offset);
            }
            None => println!("No symbol found at {:#x} in vm{}", addr, vm_id),
        }
        return;
    }

    if let Some(addr) = axebpf::guest_symbols::lookup_addr(vm_id, query) {
        println!("{} = {:#018x}", query, addr);
        return;
    }

    if let Some(addr) = parse_hex_u64(query) {
        match axebpf::guest_symbols::lookup_name(vm_id, addr) {
            Some((name, ty, offset)) if offset == 0 => {
                println!("{:#018x} {} {}", addr, ty, name);
            }
            Some((name, ty, offset)) => {
                println!("{:#018x} {} {}+{:#x}", addr, ty, name, offset);
            }
            None => println!("No symbol found at {:#x} in vm{}", addr, vm_id),
        }
        return;
    }

    println!("Symbol '{}' not found in vm{}", query, vm_id);
    let results = axebpf::guest_symbols::search(vm_id, query, 5);
    if !results.is_empty() {
        println!("Did you mean:");
        for (addr, name, ty) in &results {
            println!("  {:#018x} {} {}", addr, ty, name);
        }
    }
}

#[cfg(not(feature = "guest-kprobe"))]
fn trace_gsym(_cmd: &ParsedCommand) {
    println!("Error: guest-kprobe feature not enabled");
}

#[cfg(feature = "guest-kprobe")]
fn parse_vm_id(input: &str) -> Option<u32> {
    let vm_str = input.strip_prefix("vm")?;
    vm_str.parse().ok()
}

#[cfg(feature = "guest-kprobe")]
fn parse_hex_u64(input: &str) -> Option<u64> {
    let hex = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input);
    if hex.is_empty() {
        return None;
    }
    u64::from_str_radix(hex, 16).ok()
}

#[cfg(feature = "guest-kprobe")]
fn resolve_guest_gva(vm_id: u32, target: &str) -> Option<(u64, bool)> {
    if target.starts_with("0x") || target.starts_with("0X") {
        return match parse_hex_u64(target) {
            Some(addr) => Some((addr, false)),
            None => {
                println!("Error: invalid hex address '{}'", target);
                None
            }
        };
    }

    if let Some(addr) = axebpf::guest_symbols::lookup_addr(vm_id, target) {
        println!("Resolved '{}' -> {:#x}", target, addr);
        return Some((addr, true));
    }

    if let Some(addr) = parse_hex_u64(target) {
        return Some((addr, false));
    }

    println!("Error: symbol '{}' not found in vm{}", target, vm_id);
    if !axebpf::guest_symbols::is_loaded(vm_id) {
        println!("Hint: load symbols first with 'trace loadsyms vm{} <path>'", vm_id);
    } else {
        let results = axebpf::guest_symbols::search(vm_id, target, 5);
        if !results.is_empty() {
            println!("Did you mean:");
            for (addr, name, _) in &results {
                println!("  {} ({:#x})", name, addr);
            }
        }
    }
    None
}

/// Parse "vm<id>:<target>" format, returns (vm_id, target_str).
fn parse_vm_target(input: &str) -> Option<(u32, &str)> {
    let input = input.strip_prefix("vm")?;
    let colon_pos = input.find(':')?;
    let vm_id: u32 = input[..colon_pos].parse().ok()?;
    let target = &input[colon_pos + 1..];
    if target.is_empty() {
        return None;
    }
    Some((vm_id, target))
}

// ============================================================================
// Command Registration
// ============================================================================

/// Build the trace command tree and register it.
pub fn register_trace_commands(tree: &mut BTreeMap<String, CommandNode>) {
    let list_cmd = CommandNode::new("List all tracepoints")
        .with_handler(trace_list)
        .with_usage("trace list");

    let enable_cmd = CommandNode::new("Enable a tracepoint")
        .with_handler(trace_enable)
        .with_usage("trace enable <TRACEPOINT>... [--prog stats|printk]")
        .with_option(OptionDef::new("prog", "eBPF program to attach (stats, printk)").with_long("prog"));

    let disable_cmd = CommandNode::new("Disable a tracepoint")
        .with_handler(trace_disable)
        .with_usage("trace disable <TRACEPOINT>...");

    let stream_cmd = CommandNode::new("Stream events in real-time")
        .with_handler(trace_stream)
        .with_usage("trace stream [--filter TYPE] [-n COUNT]")
        .with_option(
            OptionDef::new("filter", "Filter by type: hprobe, kprobe, tracepoint, vm<N>")
                .with_long("filter"),
        )
        .with_option(OptionDef::new("n", "Stop after N events").with_short('n'));

    let dump_cmd = CommandNode::new("Dump buffered events")
        .with_handler(trace_dump)
        .with_usage("trace dump [--filter TYPE] [-n COUNT]")
        .with_option(OptionDef::new("filter", "Filter by type").with_long("filter"))
        .with_option(OptionDef::new("n", "Max events to show").with_short('n'));

    let stat_cmd = CommandNode::new("Show tracepoint statistics")
        .with_handler(trace_stat)
        .with_usage("trace stat [--hist EVENT] [--top N]")
        .with_option(OptionDef::new("hist", "Show latency histogram for EVENT").with_long("hist"))
        .with_option(OptionDef::new("top", "Show top N events by count").with_long("top"));

    let reset_cmd = CommandNode::new("Reset all statistics")
        .with_handler(trace_reset)
        .with_usage("trace reset");

    let load_cmd = CommandNode::new("Load and attach eBPF program")
        .with_handler(trace_load)
        .with_usage("trace load file <PATH> <TRACEPOINT> | trace load prog <ID> <TRACEPOINT>");

    let unload_cmd = CommandNode::new("Detach program from tracepoint")
        .with_handler(trace_unload)
        .with_usage("trace unload <TRACEPOINT>");

    let progs_cmd = CommandNode::new("List loaded programs")
        .with_handler(trace_progs)
        .with_usage("trace progs");

    let verbose_cmd = CommandNode::new("Control verbose output mode")
        .with_handler(trace_verbose)
        .with_usage("trace verbose [on|off]");

    let trace_node = CommandNode::new("eBPF tracepoint management")
        .with_handler(trace_help)
        .with_usage("trace <command> [options] [args...]")
        .add_subcommand(
            "help",
            CommandNode::new("Show trace help").with_handler(trace_help),
        )
        .add_subcommand("list", list_cmd)
        .add_subcommand("enable", enable_cmd)
        .add_subcommand("disable", disable_cmd)
        .add_subcommand("stream", stream_cmd)
        .add_subcommand("dump", dump_cmd)
        .add_subcommand("stat", stat_cmd)
        .add_subcommand("verbose", verbose_cmd)
        .add_subcommand("reset", reset_cmd)
        .add_subcommand("load", load_cmd)
        .add_subcommand("unload", unload_cmd)
        .add_subcommand("progs", progs_cmd)
        .add_subcommand("hprobe", CommandNode::new("Attach hprobe to VMM function")
            .with_handler(trace_hprobe)
            .with_usage("trace hprobe <SYMBOL> <PROG_NAME_OR_ID>"))
        .add_subcommand("hretprobe", CommandNode::new("Attach hretprobe to VMM function")
            .with_handler(trace_hretprobe)
            .with_usage("trace hretprobe <SYMBOL> <PROG_ID>"))
        .add_subcommand("unhprobe", CommandNode::new("Detach hprobe from VMM function")
            .with_handler(trace_unhprobe)
            .with_usage("trace unhprobe <SYMBOL>"))
        .add_subcommand("loadsyms", CommandNode::new("Load guest symbol file")
            .with_handler(trace_loadsyms)
            .with_usage("trace loadsyms vm<ID> <PATH>"))
        .add_subcommand("gsym", CommandNode::new("Look up guest symbol")
            .with_handler(trace_gsym)
            .with_usage("trace gsym vm<ID> <NAME|ADDR|search PATTERN>"))
        .add_subcommand("kprobe", CommandNode::new("Attach kprobe to guest kernel function")
            .with_handler(trace_kprobe)
            .with_usage("trace kprobe vm<ID>:<ADDR|SYMBOL> <PROG> [--inject] [--ret]")
            .with_flag(FlagDef::new("inject", "Use BRK injection mode instead of Stage-2 fault").with_long("inject"))
            .with_flag(FlagDef::new("ret", "Attach as return probe").with_long("ret")))
        .add_subcommand("unkprobe", CommandNode::new("Detach kprobe from guest kernel function")
            .with_handler(trace_unkprobe)
            .with_usage("trace unkprobe vm<ID>:<ADDR|SYMBOL>"));

    tree.insert("trace".to_string(), trace_node);
}
