//! Built-in commands
//!
//! Commands that are part of the shell itself (help, exit, clear, log, uname, ksym).

use std::println;

use super::super::parser::ParsedCommand;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};

#[cfg(feature = "ebpf")]
use axebpf::symbols;

/// Handle the `uname` command - display system information
pub fn do_uname(cmd: &ParsedCommand) {
    let show_all = cmd.flags.get("all").unwrap_or(&false);
    let show_kernel = cmd.flags.get("kernel-name").unwrap_or(&false);
    let show_arch = cmd.flags.get("machine").unwrap_or(&false);

    let arch = option_env!("AX_ARCH").unwrap_or("");
    let platform = option_env!("AX_PLATFORM").unwrap_or("");
    let smp = match option_env!("AX_SMP") {
        None | Some("1") => "",
        _ => " SMP",
    };
    let version = option_env!("CARGO_PKG_VERSION").unwrap_or("0.1.0");

    if *show_all {
        println!(
            "ArceOS {ver}{smp} {arch} {plat}",
            ver = version,
            smp = smp,
            arch = arch,
            plat = platform,
        );
    } else if *show_kernel {
        println!("ArceOS");
    } else if *show_arch {
        println!("{}", arch);
    } else {
        println!(
            "ArceOS {ver}{smp} {arch} {plat}",
            ver = version,
            smp = smp,
            arch = arch,
            plat = platform,
        );
    }
}

/// Handle the `exit` command - exit the shell
pub fn do_exit(cmd: &ParsedCommand) {
    let args = &cmd.positional_args;
    let exit_code = if args.is_empty() {
        0
    } else {
        args[0].parse::<i32>().unwrap_or(0)
    };

    println!("Bye~");
    std::process::exit(exit_code);
}

/// Handle the `log` command - change log level
pub fn do_log(cmd: &ParsedCommand) {
    let args = &cmd.positional_args;

    if args.is_empty() {
        println!("Current log level: {:?}", log::max_level());
        return;
    }

    match args[0].as_str() {
        "on" | "enable" => log::set_max_level(log::LevelFilter::Info),
        "off" | "disable" => log::set_max_level(log::LevelFilter::Off),
        "error" => log::set_max_level(log::LevelFilter::Error),
        "warn" => log::set_max_level(log::LevelFilter::Warn),
        "info" => log::set_max_level(log::LevelFilter::Info),
        "debug" => log::set_max_level(log::LevelFilter::Debug),
        "trace" => log::set_max_level(log::LevelFilter::Trace),
        level => {
            println!("Unknown log level: {}", level);
            println!("Available levels: off, error, warn, info, debug, trace");
            return;
        }
    }
    println!("Log level set to: {:?}", log::max_level());
}

/// Handle the `ksym` command - kernel symbol lookup
#[cfg(feature = "ebpf")]
pub fn do_ksym(cmd: &ParsedCommand) {
    if !symbols::is_initialized() {
        println!("Error: Symbol table not initialized");
        println!("Hint: Symbol table is loaded during boot if kallsyms is available");
        return;
    }

    let args = &cmd.positional_args;

    if args.is_empty() {
        println!("Usage: ksym <subcommand>");
        println!("  ksym lookup <name>     - Lookup symbol address by exact name");
        println!("  ksym search <pattern>  - Search symbols containing pattern");
        println!("  ksym addr <address>    - Lookup symbol by address (hex)");
        return;
    }

    match args[0].as_str() {
        "lookup" => {
            if args.len() < 2 {
                println!("Usage: ksym lookup <symbol_name>");
                return;
            }
            let name = &args[1];
            match symbols::lookup_addr(name) {
                Some(addr) => println!("{} = 0x{:x}", name, addr),
                None => println!("Symbol '{}' not found", name),
            }
        }
        "search" => {
            if args.len() < 2 {
                println!("Usage: ksym search <pattern>");
                return;
            }
            let pattern = &args[1];
            let results = symbols::search_symbols(pattern, 50);
            if results.is_empty() {
                println!("No symbols found containing '{}'", pattern);
            } else {
                println!("Found {} symbol(s) matching '{}':", results.len(), pattern);
                for (name, addr) in &results {
                    println!("  0x{:016x}  {}", addr, name);
                }
                if results.len() == 50 {
                    println!("  ... (limited to 50 results)");
                }
            }
        }
        "addr" => {
            if args.len() < 2 {
                println!("Usage: ksym addr <address>");
                return;
            }
            let addr_str = args[1].trim_start_matches("0x");
            match u64::from_str_radix(addr_str, 16) {
                Ok(addr) => match symbols::lookup_symbol(addr) {
                    Some((name, size, offset, ty)) => {
                        println!(
                            "0x{:x} = {}+0x{:x} (size: {}, type: {})",
                            addr, name, offset, size, ty
                        );
                    }
                    None => println!("No symbol found at address 0x{:x}", addr),
                },
                Err(_) => println!("Invalid address format: {}", args[1]),
            }
        }
        sub => {
            println!("Unknown subcommand: {}", sub);
            println!("Available: lookup, search, addr");
        }
    }
}

/// Register built-in commands to the command tree
pub fn register_builtin_commands(tree: &mut BTreeMap<String, super::super::parser::CommandNode>) {
    use super::super::parser::{CommandNode, FlagDef};

    // uname Command
    tree.insert(
        "uname".to_string(),
        CommandNode::new("System information")
            .with_handler(do_uname)
            .with_usage("uname [OPTIONS]")
            .with_flag(
                FlagDef::new("all", "Show all information")
                    .with_short('a')
                    .with_long("all"),
            )
            .with_flag(
                FlagDef::new("kernel-name", "Show kernel name")
                    .with_short('s')
                    .with_long("kernel-name"),
            )
            .with_flag(
                FlagDef::new("machine", "Show machine architecture")
                    .with_short('m')
                    .with_long("machine"),
            ),
    );

    // exit Command
    tree.insert(
        "exit".to_string(),
        CommandNode::new("Exit the shell")
            .with_handler(do_exit)
            .with_usage("exit [EXIT_CODE]"),
    );

    // log Command
    tree.insert(
        "log".to_string(),
        CommandNode::new("Change log level")
            .with_handler(do_log)
            .with_usage("log [LEVEL]"),
    );

    // ksym Command (only available with ebpf feature)
    #[cfg(feature = "ebpf")]
    tree.insert(
        "ksym".to_string(),
        CommandNode::new("Kernel symbol lookup")
            .with_handler(do_ksym)
            .with_usage("ksym <subcommand> [args]"),
    );
}
