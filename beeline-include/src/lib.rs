use std::{env, ffi::OsString, path::Path};
use tracing::level_filters::ParseLevelFilterError;

// TODO: add option for env var that should toggle tracing
pub fn clang_args() -> Result<Vec<OsString>, ParseLevelFilterError> {
    let mut args = vec![OsString::from("-I"), OsString::from(include_path_root())];
    args.extend_from_slice(&bpf_tracing_include::clang_args_from_default_env()?);
    Ok(args)
}

/// Returns the root path of the include directory. Note that arguments returned
/// by [`clang_args_from_env`] and [`clang_args`] already contain this path.
#[inline]
pub fn include_path_root() -> OsString {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("include");
    println!("cargo:rerun-if-changed={:?}", path);
    OsString::from(path)
}
