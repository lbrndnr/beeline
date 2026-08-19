use anyhow::Result;
use xbpf::libbpf::{Mut, OpenProgramImpl};

#[cfg(feature = "build")]
pub mod build;

#[cfg(feature = "h1")]
pub mod h1;

#[cfg(feature = "h2")]
pub mod h2;

pub mod header {
    pub const METHOD: http::HeaderName = http::HeaderName::from_static("method");
    pub const PATH: http::HeaderName = http::HeaderName::from_static("path");
    pub const STATUS: http::HeaderName = http::HeaderName::from_static("status");
}

fn autoload_and_attach<'obj>(
    prog: &mut OpenProgramImpl<'obj, Mut>,
    target: i32,
    name: Option<String>,
) -> Result<()> {
    prog.set_autoload(name.is_some());
    prog.set_attach_target(target, name)?;
    Ok(())
}
