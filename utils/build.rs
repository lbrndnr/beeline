use libbpf_cargo::SkeletonBuilder;
use std::{env, ffi::OsStr, path::PathBuf};

fn main() {
    let manifest_dir =
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script");
    let manifest_dir = PathBuf::from(&manifest_dir);

    let src = PathBuf::from(&manifest_dir).join("src").join("prog.bpf.c");
    println!("cargo:rerun-if-changed={src:?}");

    let out = PathBuf::from(&manifest_dir)
        .join("src")
        .join("prog.skel.rs");
    SkeletonBuilder::new()
        .source(&src)
        .clang_args([OsStr::new("-I"), OsStr::new("../include")])
        .build_and_generate(&out)
        .unwrap();
}
