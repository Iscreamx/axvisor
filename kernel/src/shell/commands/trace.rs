//! Trace commands for eBPF tracepoint management.
//!
//! Commands for listing, enabling, disabling tracepoints and viewing statistics.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};

use axstd::println;

use super::super::parser::{CommandNode, OptionDef, ParsedCommand};

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
    println!("  stat                              Show tracepoint statistics");
    println!("  verbose [on|off]                  Control real-time eBPF output");
    println!("  reset                             Reset all statistics");
    println!("  load file <path> <tp>             Load eBPF program from file and attach");
    println!("  load prog <id> <tp>               Attach loaded program to tracepoint");
    println!("  unload <tp>                       Detach program from tracepoint");
    println!("  progs                             List pre-compiled and loaded programs");
    println!();
    println!("Pre-compiled programs:");
    println!("  stats    - Event counter with latency (COUNT/TOTAL/MIN/MAX)");
    println!("  printk   - Debug logger with count");
    println!();
    println!("Examples:");
    println!("  trace enable vmm:vcpu_run_enter");
    println!("  trace enable vmm:vcpu_run_exit --prog stats");
    println!("  trace enable shell:shell_command --prog printk");
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
                    match runtime::load_program(precompiled.bytecode) {
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
fn trace_stat(_cmd: &ParsedCommand) {
    use axebpf::{attach, maps, runtime};

    let attachments = attach::list_attachments();

    if attachments.is_empty() {
        println!("No programs attached. Statistics are collected by eBPF programs.");
        println!("Use 'trace enable <tracepoint> --prog stats' to start collecting.");
        return;
    }

    // Part 1: Attachment table
    println!(
        "{:<30} {:>8} {:<12} {:>8}",
        "TRACEPOINT", "PROG_ID", "PROG_NAME", "STATUS"
    );
    println!(
        "{:-<30} {:-<8} {:-<12} {:-<8}",
        "", "", "", ""
    );

    for (tp_name, info) in &attachments {
        let status = if runtime::get_program(info.prog_id).is_some() {
            "active"
        } else {
            "invalid"
        };
        println!(
            "{:<30} {:>8} {:<12} {:>8}",
            tp_name,
            info.prog_id,
            info.prog_name,
            status,
        );
    }

    println!();

    // Part 2: Map data table
    println!("MAP DATA:");
    println!(
        "{:<30} {:<16} {:>10} {:>12}",
        "TRACEPOINT", "MAP_NAME", "KEY", "VALUE"
    );
    println!(
        "{:-<30} {:-<16} {:-<10} {:-<12}",
        "", "", "", ""
    );

    let mut total_entries = 0;

    for (tp_name, info) in &attachments {
        if let Some(map_fds) = runtime::get_program_map_fds(info.prog_id) {
            for (map_name, map_fd) in map_fds {
                let entries = maps::iter_entries(map_fd);
                for (key, value) in &entries {
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
                        "{:<30} {:<16} {:>10} {:>12}",
                        tp_name,
                        map_name,
                        key_val,
                        value_val,
                    );
                    total_entries += 1;
                }
            }
        }
    }

    if total_entries == 0 {
        println!("  (no map entries yet)");
    }

    println!();
    println!("Total: {} programs, {} map entries", attachments.len(), total_entries);
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

    let prog_id = match runtime::load_program(&bytecode) {
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

    let stat_cmd = CommandNode::new("Show tracepoint statistics")
        .with_handler(trace_stat)
        .with_usage("trace stat");

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
        .add_subcommand("stat", stat_cmd)
        .add_subcommand("verbose", verbose_cmd)
        .add_subcommand("reset", reset_cmd)
        .add_subcommand("load", load_cmd)
        .add_subcommand("unload", unload_cmd)
        .add_subcommand("progs", progs_cmd);

    tree.insert("trace".to_string(), trace_node);
}
