use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;

/// eBPF 程序名列表
const EBPF_PROGRAMS: &[&str] = &["stats", "printk"];

/// 编译单个 eBPF 程序
fn build_program(name: &str, source_dir: &Path, output_dir: &Path) -> Result<()> {
    println!("  Building {}...", name);

    let status = Command::new("cargo")
        .current_dir(source_dir)
        .args([
            "+nightly",
            "build",
            "--release",
            "--bin", name,
            "-Z", "build-std=core",
            "--target", "bpfel-unknown-none",
        ])
        .status()
        .context(format!("Failed to run cargo build for {}", name))?;

    if !status.success() {
        bail!("Failed to build eBPF program: {}", name);
    }

    // 复制输出文件到目标目录
    let src_path = source_dir
        .join("target/bpfel-unknown-none/release")
        .join(name);
    let dst_path = output_dir.join(format!("{}.o", name));

    std::fs::copy(&src_path, &dst_path)
        .context(format!("Failed to copy {} to {}", src_path.display(), dst_path.display()))?;

    println!("    -> {}", dst_path.display());
    Ok(())
}

/// 构建所有 eBPF 程序
pub fn build_ebpf() -> Result<()> {
    println!("Building eBPF programs...");

    let workspace_root = std::env::current_dir()?;
    let source_dir = workspace_root.join("ebpf-programs");
    let output_dir = workspace_root.join("target/bpf");

    // 确保源码目录存在
    if !source_dir.exists() {
        bail!(
            "eBPF source directory not found: {}\n\
             Run this command from the workspace root.",
            source_dir.display()
        );
    }

    // 创建输出目录
    std::fs::create_dir_all(&output_dir)
        .context("Failed to create target/bpf directory")?;

    // 编译每个程序
    for name in EBPF_PROGRAMS {
        build_program(name, &source_dir, &output_dir)?;
    }

    println!();
    println!("eBPF programs built successfully!");
    println!("Output directory: {}", output_dir.display());

    Ok(())
}
