use anyhow::Result;
use libbpf_rs::{Mut, OpenProgramImpl, PrintLevel};
#[cfg(feature = "h2")]
use std::net::SocketAddr;
use tracing::{debug, info, warn};

#[cfg(feature = "h1")]
pub mod h1;

#[cfg(feature = "h2")]
pub mod h2;

pub mod header {
    pub const METHOD: http::HeaderName = http::HeaderName::from_static("method");
    pub const PATH: http::HeaderName = http::HeaderName::from_static("path");
    pub const STATUS: http::HeaderName = http::HeaderName::from_static("status");
}

impl From<SocketAddr> for h2::ip4_addr {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(addr) => h2::ip4_addr {
                ip4: u32::from_ne_bytes(addr.ip().octets()),
                port: addr.port() as u32,
            },
            SocketAddr::V6(_) => panic!("ip4_addr does not support IPv6 addresses"),
        }
    }
}

fn print(level: PrintLevel, msg: String) {
    let msg = msg.trim_start_matches("libbpf:").trim();

    match level {
        PrintLevel::Debug => debug!(target: "libbpf", "{}", msg),
        PrintLevel::Info => info!(target: "libbpf", "{}", msg),
        PrintLevel::Warn => warn!(target: "libbpf", "{}", msg),
    }
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
