//! Application-layer parsing in eBPF.
//!
//! Beeline compiles a set of header patterns into a DFA, injects that DFA into
//! a pre-compiled BPF parser program and attaches the parser to another BPF
//! program with `freplace`. Messages are therefore parsed in the kernel, as
//! part of the program that uses the parser, and never have to be copied to
//! user space.
//!
//! The target program declares the functions it wants Beeline to provide with
//! the `BEEPS_*` macros of `beeps.h` and then names them in the [`h1`] or
//! [`h2`] builder:
//!
//! ```no_run
//! # fn main() -> anyhow::Result<()> {
//! # let prog_fd = 0;
//! use beeps::{h1, header::PATH};
//!
//! let parser = h1::Parser::new()
//!     .capture_hdr(&PATH)
//!     .replace_parse_msg("parse_h1")
//!     .replace_extract("extract_h1_match")
//!     .attach(prog_fd)?;
//! # Ok(())
//! # }
//! ```
//!
//! The value returned by `attach` owns the links to the attached programs, so
//! the parser stays in place until it is dropped.

use anyhow::Result;
use xbpf::libbpf::{Mut, OpenProgramImpl};

#[cfg(feature = "build")]
pub mod build;

#[cfg(feature = "h1")]
pub mod h1;

#[cfg(feature = "h2")]
pub mod h2;

/// The names Beeline uses to address the fields of a request or status line.
///
/// HTTP/2 carries them as pseudo-headers, HTTP/1.x as part of the first line
/// of a message. They are spelled without the leading colon of their HTTP/2
/// counterparts so that a single [`http::HeaderName`] addresses the same field
/// in both protocols.
pub mod header {
    /// The method of a request, e.g. `GET`.
    pub const METHOD: http::HeaderName = http::HeaderName::from_static("method");
    /// The path a request is addressed to, e.g. `/index.html`.
    pub const PATH: http::HeaderName = http::HeaderName::from_static("path");
    /// The status code of a response, e.g. `200`.
    pub const STATUS: http::HeaderName = http::HeaderName::from_static("status");
}

/// Points `prog` at the function it replaces in the target program.
///
/// `name` is the name of that function in the program `target` refers to, or
/// `None` if the caller did not configure `prog`, in which case it is left
/// unloaded.
fn autoload_and_attach<'obj>(
    prog: &mut OpenProgramImpl<'obj, Mut>,
    target: i32,
    name: Option<String>,
) -> Result<()> {
    prog.set_autoload(name.is_some());
    prog.set_attach_target(target, name)?;
    Ok(())
}
