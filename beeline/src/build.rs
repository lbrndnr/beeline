use std::{ffi::OsString, path::Path};

/// Returns the clang arguments that should be passed to [`SkeletonBuilder`].
pub fn clang_args() -> Vec<OsString> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("include");
    println!("cargo:rerun-if-changed={}", path.display());
    vec![OsString::from("-I"), OsString::from(path)]
}
