use libbpf_cargo::SkeletonBuilder;
use std::{
    env,
    ffi::OsStr,
    fs::{self, File},
    io::Write,
    path::PathBuf,
};

fn main() {
    let manifest_dir =
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script");
    let manifest_dir = PathBuf::from(&manifest_dir);
    let target_dir = manifest_dir.join("..").join("target").join("bpf");

    match fs::create_dir(&target_dir) {
        Ok(_) => Ok(()),
        Err(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
    .expect("Failed to create target/bpf");

    let prog = PathBuf::from(&manifest_dir)
        .join("..")
        .join("utils")
        .join("src")
        .join("prog.bpf.c");
    let prog = fs::read_to_string(prog).expect("Failed to read prog file");
    println!("cargo:rerun-if-changed={prog:?}");

    let beeline = PathBuf::from(&manifest_dir)
        .join("src")
        .join("beeline.bpf.c");
    let beeline = fs::read_to_string(beeline).expect("Failed to read beeline file");
    println!("cargo:rerun-if-changed={beeline:?}");

    let out = PathBuf::from(&target_dir).join("prog.bpf.c");
    let mut file = File::create(&out).expect("Failed to create src file");
    file.write_all(prog.as_bytes())
        .expect("Failed to write to src file");
    file.write_all(beeline.as_bytes())
        .expect("Failed to write to src file");

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

    let src = out.to_str().unwrap();
    let out = PathBuf::from(manifest_dir)
        .join("..")
        .join("utils")
        .join("src")
        .join("prog.skel.rs");
    SkeletonBuilder::new()
        .source(src)
        .clang_args([
            OsStr::new("-D"),
            OsStr::new(format!("BL_LOG_LEVEL={log_level}").as_str()),
            OsStr::new("-I"),
            OsStr::new("include"),
        ])
        .build_and_generate(&out)
        .unwrap();

    println!("cargo:rerun-if-changed={src}");
    println!("cargo:rerun-if-changed=include/beeline.h");
}
