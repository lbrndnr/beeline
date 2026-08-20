//! Build script support for programs that use a Beeper parser.
//!
//! Enable the `build` feature and call [`clang_args`] from the build script of
//! the crate whose BPF programs include `beeper.h`.

use std::{ffi::OsString, path::Path};

/// Returns the clang arguments that make `beeper.h` includable, i.e. the
/// include path of Beeper's own headers.
///
/// Pass them to the skeleton builder that compiles the BPF programs of the
/// calling crate.
pub fn clang_args() -> Vec<OsString> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("include");
    println!("cargo:rerun-if-changed={}", path.display());
    vec![OsString::from("-I"), OsString::from(path)]
}
