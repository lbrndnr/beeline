use libbpf_cargo::SkeletonBuilder;
use std::{env, ffi::OsString, path::PathBuf};

fn main() {
    // let manifest_dir =
    //     env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script");
    // let manifest_dir = PathBuf::from(&manifest_dir);

    // let src = PathBuf::from(&manifest_dir).join("src").join("prog.bpf.c");
    // println!("cargo:rerun-if-changed={src:?}");

    // let out_dir = env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script");
    // let out_dir = PathBuf::from(&out_dir);
    // let out = out_dir.clone().join("prog.skel.rs");

    // let mut args = vec![OsString::from("-I"), OsString::from("../include")];
    // args.extend_from_slice(&beeline_include::clang_args().unwrap());

    // SkeletonBuilder::new()
    //     .source(&src)
    //     .clang_args(args)
    //     .build_and_generate(&out)
    //     .unwrap();
}
