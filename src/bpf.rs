use std::net::{IpAddr, SocketAddr};

use anyhow::{Result, bail};

pub trait TryIntoRawOctets {
    fn try_into_ne_octets(&self) -> Result<u32>;
}

impl TryIntoRawOctets for SocketAddr {
    fn try_into_ne_octets(&self) -> Result<u32> {
        match self {
            SocketAddr::V4(addr) => Ok(u32::from_ne_bytes(addr.ip().octets())),
            _ => bail!("TryIntoRawOctets only supports IPv4 addresses"),
        }
    }
}

impl TryIntoRawOctets for IpAddr {
    fn try_into_ne_octets(&self) -> Result<u32> {
        match self {
            IpAddr::V4(ip) => Ok(u32::from_ne_bytes(ip.octets())),
            _ => bail!("TryIntoRawOctets only supports IPv4 addresses"),
        }
    }
}
