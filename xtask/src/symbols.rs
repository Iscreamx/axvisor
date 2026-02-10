use std::{collections::HashMap, fmt::Debug, io::Write, fs::File, path::Path};
use anyhow::{Result, Context};
use ksym::TOKEN_MARKER;

/// Candidate prefix lengths for heuristic tokenization
const PREFIX_CANDIDATE_LENS: &[usize] = &[
    10, 24, 31, 40, 56, 60, 70, 80, 90, 100, 150, 200, 250, 300, 400, 500, 600, 700, 800, 900,
    1000, 1200, 1400, 1600, 1800, 2000,
];

/// Maximum number of tokens
const MAX_TOKEN: usize = 512;

/// The structure for compressed symbol data
pub struct KallsymsBlob {
    pub token_table: Vec<u8>,
    /// The start index of each token in token_table
    pub token_index: Vec<u32>,
    pub token_map: HashMap<String, u16>,
    /// Compressed symbol data
    pub kallsyms_names: Vec<u8>,
    /// The offsets of each symbol in kallsyms_names
    pub kallsyms_offsets: Vec<u32>,
    /// The sequence numbers of each symbol
    pub kallsyms_seqs_of_names: Vec<u32>,
    /// The addresses of each symbol
    pub kallsyms_addresses: Vec<u64>,
    pub kallsyms_num_syms: usize,
}

impl Debug for KallsymsBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KallsymsBlob")
            .field("token_table size", &(self.token_table.len()))
            .field("token_index size", &(self.token_index.len() * 4))
            .field("kallsyms_names size", &(self.kallsyms_names.len()))
            .field("kallsyms_offsets size", &(self.kallsyms_offsets.len() * 4))
            .field(
                "kallsyms_seqs_of_names size",
                &(self.kallsyms_seqs_of_names.len() * 4),
            )
            .field(
                "kallsyms_addresses size",
                &(self.kallsyms_addresses.len() * 8),
            )
            .field("kallsyms_num_syms", &self.kallsyms_num_syms)
            .finish()
    }
}

impl KallsymsBlob {
    pub fn new() -> Self {
        Self {
            token_table: Vec::new(),
            token_index: Vec::new(),
            token_map: HashMap::new(),
            kallsyms_names: Vec::new(),
            kallsyms_offsets: Vec::new(),
            kallsyms_seqs_of_names: Vec::new(),
            kallsyms_addresses: Vec::new(),
            kallsyms_num_syms: 0,
        }
    }

    /// Add a token to the token table
    fn add_token(&mut self, token: String) -> Option<u16> {
        if let Some(&id) = self.token_map.get(&token) {
            return Some(id);
        }
        let id = self.token_map.len() as u16;
        self.token_index.push(self.token_table.len() as u32);
        self.token_table.extend_from_slice(token.as_bytes());
        self.token_map.insert(token, id);
        Some(id)
    }

    /// Compress all symbol names, auto-generating tokens.
    /// Storage order: address order, with a name-order to address-order mapping.
    pub fn compress_symbols(&mut self, symbols: &[(String, u64, char)]) {
        // 0) Build indices for name order and address order.
        let n = symbols.len();
        if n == 0 {
            return;
        }
        let mut idx_by_addr: Vec<usize> = (0..n).collect();
        idx_by_addr.sort_by_key(|&i| symbols[i].1);
        let mut idx_by_name: Vec<usize> = (0..n).collect();
        idx_by_name.sort_by(|&i, &j| symbols[i].0.cmp(&symbols[j].0));

        // map original index -> address-order index
        let mut orig_to_addr_idx = vec![0usize; n];
        for (addr_pos, &orig_idx) in idx_by_addr.iter().enumerate() {
            orig_to_addr_idx[orig_idx] = addr_pos;
        }

        // 1) Count possible tokens using prefix-based heuristic.
        // For each symbol, consider only prefixes of specific lengths.
        let mut token_count: HashMap<String, usize> = HashMap::new();
        for (name, _, _) in symbols.iter() {
            let bytes = name.as_bytes();
            for &len in PREFIX_CANDIDATE_LENS {
                if bytes.len() >= len {
                    let token = std::str::from_utf8(&bytes[..len]).unwrap();
                    *token_count.entry(token.to_string()).or_insert(0) += 1;
                } else if !bytes.is_empty() && len == PREFIX_CANDIDATE_LENS[0] {
                    // Edge case: name shorter than the smallest candidate length; include full name to avoid missing short common prefixes
                    let token = name;
                    *token_count.entry(token.to_string()).or_insert(0) += 1;
                }
            }
        }

        // 2) Select high-frequency tokens (cap at MAX_TOKEN), prefer longer tokens on tie
        let mut tokens: Vec<(String, usize)> = token_count.into_iter().collect();
        tokens.sort_by(|a, b| {
            // primary: frequency desc; secondary: length desc;
            // b.1.cmp(&a.1).then_with(|| b.0.len().cmp(&a.0.len()))
            (b.1 * b.0.len()).cmp(&(a.1 * a.0.len())) // weighted by length(more effective)
        });
        let mut final_token_list: Vec<String> = Vec::new();
        for (tok, _) in tokens.into_iter() {
            if final_token_list.len() >= MAX_TOKEN {
                break;
            }
            // Avoid tokens that are prefixes of existing tokens
            let mut is_prefix = false;
            for existing in &final_token_list {
                if existing.starts_with(&tok) {
                    is_prefix = true;
                    break;
                }
            }
            if !is_prefix {
                final_token_list.push(tok);
            }
        }
        for tok in final_token_list.into_iter() {
            self.add_token(tok);
        }

        // 3) Compress symbols in address order and build offsets/addresses.
        for &orig_idx in &idx_by_addr {
            let (ref sym, addr, ty) = symbols[orig_idx];
            self.kallsyms_offsets.push(self.kallsyms_names.len() as u32);
            self.kallsyms_addresses.push(addr);

            let sym_bytes = sym.as_bytes();
            // Only allow a single token at the beginning (prefix) according to heuristic.
            let rem = sym_bytes.len();
            let mut consumed = 0usize;
            for &l in PREFIX_CANDIDATE_LENS.iter().rev() {
                if l > rem {
                    // if the candidate length exceeds the remaining length, skip
                    continue;
                }
                let candidate = &sym[..l];
                if let Some(&id) = self.token_map.get(candidate) {
                    // 1. [type] [length] (0xff  token             0xff) [remaining bytes]
                    // 2. [type] [length] (0xff  token_hi token_lo 0xff) [remaining bytes]
                    //    [1byte][2bytes] (1byte 1byte    1byte   1byte) [remaining bytes]
                    let mut length: u16 = if id < 256 { 3 } else { 4 };
                    length += (rem - l) as u16;
                    // Emit type char
                    self.kallsyms_names.push(ty as u8);

                    // Emit length (little-endian: lo, hi)
                    self.kallsyms_names.push((length & 0xFF) as u8);
                    self.kallsyms_names.push((length >> 8) as u8);

                    // Emit token
                    self.kallsyms_names.push(TOKEN_MARKER);
                    if id < 256 {
                        self.kallsyms_names.push(id as u8);
                    } else {
                        self.kallsyms_names.push((id >> 8) as u8);
                        self.kallsyms_names.push((id & 0xFF) as u8);
                    }
                    self.kallsyms_names.push(TOKEN_MARKER);
                    consumed = l;
                    break;
                }
            }

            if consumed == 0 {
                // No token matched; emit full symbol as raw bytes
                // Emit type char
                self.kallsyms_names.push(ty as u8);
                // Emit length
                let length = rem as u16;
                // little-endian: lo, hi
                self.kallsyms_names.push((length & 0xFF) as u8);
                self.kallsyms_names.push((length >> 8) as u8);
            }

            // Emit remaining bytes raw
            self.kallsyms_names
                .extend_from_slice(&sym_bytes[consumed..]);
        }

        // 4) Build name-order -> address-order sequence mapping.
        self.kallsyms_seqs_of_names.reserve(n);
        for &orig_idx in &idx_by_name {
            let addr_idx = orig_to_addr_idx[orig_idx] as u32;
            self.kallsyms_seqs_of_names.push(addr_idx);
        }

        self.kallsyms_num_syms = n;
    }

    /// Serialize blob into bytes
    /// Convert the blob into binary data
    pub fn to_blob(&self) -> Vec<u8> {
        let mut blob = Vec::new();

        #[inline]
        fn pad(vec: &mut Vec<u8>, align: usize) {
            let rem = vec.len() % align;
            if rem != 0 {
                vec.resize(vec.len() + (align - rem), 0);
            }
        }

        blob.extend_from_slice(&(self.kallsyms_num_syms as u64).to_le_bytes());

        // addresses [u64]
        pad(&mut blob, 8);
        for &addr in &self.kallsyms_addresses {
            blob.extend_from_slice(&addr.to_le_bytes());
        }
        // offsets [u32]
        pad(&mut blob, 4);
        for &off in &self.kallsyms_offsets {
            blob.extend_from_slice(&(off as u32).to_le_bytes());
        }
        // seqs [u32]
        pad(&mut blob, 4);
        for &seq in &self.kallsyms_seqs_of_names {
            blob.extend_from_slice(&seq.to_le_bytes());
        }

        // names bytes (len u64 + bytes)
        pad(&mut blob, 8);
        blob.extend_from_slice(&(self.kallsyms_names.len() as u64).to_le_bytes());
        blob.extend_from_slice(&self.kallsyms_names);

        // token table bytes (len u64 + bytes)
        pad(&mut blob, 8);
        blob.extend_from_slice(&(self.token_table.len() as u64).to_le_bytes());
        blob.extend_from_slice(&self.token_table);

        // token index [u32] (len u64 + array)
        pad(&mut blob, 8);
        blob.extend_from_slice(&(self.token_index.len() as u64).to_le_bytes());
        pad(&mut blob, 4);
        for &idx in &self.token_index {
            blob.extend_from_slice(&idx.to_le_bytes());
        }

        blob
    }
}

pub fn generate_symbols(kernel_path: &Path, output_path: &Path) -> Result<()> {
    println!("Generating symbols from {:?} to {:?}", kernel_path, output_path);

    // In a real implementation, we would parse the ELF file to extract symbols.
    // For now, we'll try to run `nm` command.
    let output = std::process::Command::new("nm")
        .arg("-n") // sort by address
        .arg(kernel_path)
        .output()
        .context("Failed to run nm")?;

    if !output.status.success() {
        return Err(anyhow::anyhow!("nm failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut symbols = Vec::new();

    for line in stdout.lines() {
        if let Some((sym, addr, ty)) = read_symbol(line) {
            symbols.push((sym, addr, ty));
        }
    }

    println!("Parsed {} symbols", symbols.len());

    let mut blob = KallsymsBlob::new();
    blob.compress_symbols(&symbols);
    let binary_blob = blob.to_blob();

    let mut file = File::create(output_path).context("Failed to create output file")?;
    file.write_all(&binary_blob).context("Failed to write blob")?;

    println!("Symbol table generated, size: {} bytes", binary_blob.len());
    Ok(())
}

/// Maximum size of the .kallsyms section placeholder in the kernel binary.
/// Must match `KALLSYMS_RESERVE_SIZE` in `kernel/src/main.rs`.
const KALLSYMS_RESERVE_SIZE: usize = 512 * 1024;

/// Inject kallsyms.bin into the .kallsyms ELF section via rust-objcopy.
///
/// The kernel binary contains a fixed-size placeholder array in the
/// `.kallsyms` section. This function replaces that placeholder with
/// the actual compressed symbol table data generated by `generate_symbols`.
///
/// # Errors
///
/// Returns an error if:
/// - `kallsyms.bin` exceeds `KALLSYMS_RESERVE_SIZE` (512 KB)
/// - `rust-objcopy` is not installed or fails
pub fn inject_kallsyms(elf_path: &Path, kallsyms_path: &Path) -> Result<()> {
    let kallsyms_size = std::fs::metadata(kallsyms_path)
        .with_context(|| format!("Failed to read {}", kallsyms_path.display()))?
        .len() as usize;

    if kallsyms_size > KALLSYMS_RESERVE_SIZE {
        anyhow::bail!(
            "kallsyms.bin ({} bytes) exceeds reserve size ({} bytes). \
             Increase KALLSYMS_RESERVE_SIZE in kernel/src/main.rs and xtask/src/symbols.rs.",
            kallsyms_size,
            KALLSYMS_RESERVE_SIZE
        );
    }

    let status = std::process::Command::new("rust-objcopy")
        .arg("--update-section")
        .arg(format!(".kallsyms={}", kallsyms_path.display()))
        .arg(elf_path)
        .status()
        .context("Failed to run rust-objcopy. Is cargo-binutils installed?")?;

    if !status.success() {
        anyhow::bail!("rust-objcopy --update-section failed");
    }

    println!(
        "Injected kallsyms ({} bytes, {:.1}% of {} reserve) into {}",
        kallsyms_size,
        (kallsyms_size as f64 / KALLSYMS_RESERVE_SIZE as f64) * 100.0,
        KALLSYMS_RESERVE_SIZE,
        elf_path.display()
    );
    Ok(())
}

fn read_symbol(line: &str) -> Option<(String, u64, char)> {
    if line.len() > 4096 {
        // Skip too long symbols
        return None;
    }
    let mut parts = line.split_whitespace();
    let addr_str = parts.next()?;
    let vaddr = u64::from_str_radix(addr_str, 16).ok()?;
    let symbol_type = parts.next()?.chars().next()?;
    let symbol_part = parts.collect::<Vec<_>>().join(" ");
    if symbol_part.is_empty() {
        return None;
    }

    let mut symbol = symbol_part;
    if symbol.starts_with("_ZN") {
        symbol = format!("{:#}", rustc_demangle::demangle(&symbol));
    }

    Some((symbol, vaddr, symbol_type))
}
