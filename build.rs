use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/h2/parser.bpf.c";

fn main() {
    let manifest_dir =
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script");
    let out = PathBuf::from(manifest_dir)
        .join("src")
        .join("h2")
        .join("parser.skel.rs");

    let log_level = std::env::var("RUST_LOG").map(|s| s.to_lowercase());
    let log_level: u32 = match log_level.as_deref() {
        Ok("debug") => 2,
        Ok("trace") => 2,
        Ok("info") => 1,
        Ok("warn") => 1,
        Ok("error") => 1,
        _ => 0,
    };
    println!("cargo:rerun-if-env-changed=RUST_LOG");

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([
            OsStr::new("-D"),
            OsStr::new(format!("LOG_LEVEL={log_level}").as_str()),
            OsStr::new("-I"),
            OsStr::new("include"),
        ])
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
    println!("cargo:rerun-if-changed=include/beeline.h");
}
