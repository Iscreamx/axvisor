#![no_std]

//! eBPF programs for AxVisor tracing.
//!
//! This crate contains pre-compiled eBPF programs:
//! - counter: Event counter
//! - latency: Latency histogram
//! - printk: Debug logger

pub mod common;
