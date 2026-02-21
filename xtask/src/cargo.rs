use ostool::build::CargoRunnerKind;
use std::{fs, path::PathBuf};

use crate::ctx::Context;

impl Context {
    pub async fn run_qemu(&mut self, config_path: Option<PathBuf>) -> anyhow::Result<()> {
        let build_config = self.load_config()?;

        let arch = if build_config.target.contains("aarch64") {
            Arch::Aarch64
        } else if build_config.target.contains("x86_64") {
            Arch::X86_64
        } else {
            return Err(anyhow::anyhow!(
                "Unsupported target architecture: {}",
                build_config.target
            ));
        };

        let config_path = if let Some(path) = config_path {
            path
        } else {
            PathBuf::from(format!(".qemu-{arch:?}.toml").to_lowercase())
        };

        // If the configuration file does not exist, copy from the default location
        if !config_path.exists() {
            fs::copy(
                PathBuf::from("scripts")
                    .join("ostool")
                    .join(format!("qemu-{arch:?}.toml").to_lowercase()),
                &config_path,
            )?;
        }

        // Build first, then inject symbols before running QEMU.
        // cargo_run uses cargo run which invokes the ostool runner;
        // the runner converts ELF→bin independently, so we only need
        // to ensure the ELF has symbols before that happens.
        self.ctx.cargo_build(&build_config).await?;

        let kernel_path = PathBuf::from("target")
            .join(&build_config.target)
            .join("release")
            .join("axvisor");

        if kernel_path.exists() {
            let kallsyms_path = PathBuf::from("kallsyms.bin");

            // Always regenerate kallsyms for the current build to avoid stale
            // symbol/address mismatches across incremental builds.
            println!("Generating kernel symbols...");
            match crate::symbols::generate_symbols(&kernel_path, &kallsyms_path) {
                Ok(()) => {
                    if let Err(e) = crate::symbols::inject_kallsyms(&kernel_path, &kallsyms_path) {
                        eprintln!("Warning: Failed to inject symbols: {}", e);
                    }
                }
                Err(e) => {
                    eprintln!("Warning: Failed to generate symbols: {}", e);
                    eprintln!("Warning: Skip kallsyms injection to avoid using stale symbol data");
                }
            }
        }

        let kind = CargoRunnerKind::Qemu {
            qemu_config: Some(config_path),
            debug: false,
            dtb_dump: false,
        };

        self.ctx.cargo_run(&build_config, &kind).await?;

        Ok(())
    }

    pub async fn run_uboot(&mut self, config_path: Option<PathBuf>) -> anyhow::Result<()> {
        let build_config = self.load_config()?;

        let config_path = config_path.unwrap_or_else(|| PathBuf::from(".uboot.toml"));

        let kind = CargoRunnerKind::Uboot {
            uboot_config: Some(config_path),
        };

        self.ctx.cargo_run(&build_config, &kind).await?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
enum Arch {
    Aarch64,
    X86_64,
}
