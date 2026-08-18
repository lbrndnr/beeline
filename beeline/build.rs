use libbpf_cargo::SkeletonBuilder;
use std::{env, ffi::OsString, fs, path::PathBuf};

fn build_and_generate(dir: &PathBuf) {
    let last_path_comp = dir.iter().last().unwrap().to_str().unwrap();
    let src = dir.clone().join("parser.bpf.c");
    println!("cargo:rerun-if-changed={}", src.display());

    let out_dir = env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script");
    let out_dir = PathBuf::from(&out_dir).join(last_path_comp);
    fs::create_dir_all(&out_dir).unwrap();
    let out = out_dir.clone().join("parser.skel.rs");

    let mut args = vec![OsString::from("-I"), OsString::from("../include")];
    args.extend_from_slice(&beeline_include::clang_args().unwrap());

    SkeletonBuilder::new()
        .source(&src)
        .clang_args(args)
        .build_and_generate(&out)
        .unwrap();
}

fn main() {
    let manifest_dir =
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script");
    let manifest_dir = PathBuf::from(&manifest_dir);

    let h1 = PathBuf::from(&manifest_dir).join("src").join("h1");
    build_and_generate(&h1);

    let h2 = PathBuf::from(&manifest_dir).join("src").join("h2");
    build_and_generate(&h2);

    let hdr = PathBuf::from(&manifest_dir)
        .join("..")
        .join("include")
        .join("beeline.h");
    println!("cargo:rerun-if-changed={}", hdr.display());
}
