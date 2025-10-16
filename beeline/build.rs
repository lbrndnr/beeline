use libbpf_cargo::SkeletonBuilder;
use std::{env, ffi::OsStr, path::PathBuf};

fn build_and_generate(dir: &PathBuf, log_level: u32) {
    let src = dir.clone().join("parser.bpf.c");
    println!("cargo:rerun-if-changed={src:?}");

    let out = dir.clone().join("parser.skel.rs");
    SkeletonBuilder::new()
        .source(&src)
        .clang_args([
            OsStr::new("-D"),
            OsStr::new(format!("BL_LOG_LEVEL={log_level}").as_str()),
            OsStr::new("-I"),
            OsStr::new("../include"),
        ])
        .build_and_generate(&out)
        .unwrap();
}

fn main() {
    let manifest_dir =
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script");
    let manifest_dir = PathBuf::from(&manifest_dir);

    let log_level = std::env::var("BL_LOG")
        .or(std::env::var("RUST_LOG"))
        .map(|s| s.to_lowercase());
    let log_level: u32 = match log_level.as_deref() {
        Ok("debug") => 2,
        Ok("trace") => 2,
        Ok("info") => 1,
        Ok("warn") => 1,
        Ok("error") => 1,
        _ => 0,
    };
    println!("cargo:rerun-if-env-changed=RUST_LOG");
    println!("cargo:rerun-if-env-changed=BL_LOG");

    let h1 = PathBuf::from(&manifest_dir).join("src").join("h1");
    build_and_generate(&h1, log_level);

    let h2 = PathBuf::from(&manifest_dir).join("src").join("h2");
    build_and_generate(&h2, log_level);
}
