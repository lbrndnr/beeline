#![allow(unused_imports)]

use anyhow::Result;
use as_bytes::AsBytes;
use beeline::{h2::Parser, h2::dfa::Action};
use libbpf_rs::{
    Link, MapCore, MapFlags, MapHandle, MapType, PrintLevel, set_print,
    skel::{OpenSkel, SkelBuilder},
};
use log::{debug, info, log_enabled, warn};
use std::{
    io::{Error, ErrorKind},
    mem::MaybeUninit,
    net::{SocketAddr, ToSocketAddrs},
    ops::{Deref, DerefMut},
    os::{
        fd::{AsFd, AsRawFd, IntoRawFd},
        unix::fs::OpenOptionsExt,
    },
};
use types::*;

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/prog.skel.rs"));

fn print(level: PrintLevel, msg: String) {
    let msg = msg.trim_start_matches("libbpf:").trim();

    match level {
        PrintLevel::Debug => debug!(target: "libbpf", "{}", msg),
        PrintLevel::Info => info!(target: "libbpf", "{}", msg),
        PrintLevel::Warn => warn!(target: "libbpf", "{}", msg),
    }
}

pub struct TestProgram<'obj> {
    skel: ProgSkel<'obj>,
    #[allow(dead_code)]
    sockops: Link,
}

unsafe impl<'obj> Send for TestProgram<'obj> {}

unsafe impl<'obj> Sync for TestProgram<'obj> {}

impl<'obj> TestProgram<'obj> {
    pub fn attach<A: ToSocketAddrs>(
        address: A,
        open_obj: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
    ) -> Result<Self> {
        set_print(Some((PrintLevel::Debug, print)));

        let address = address
            .to_socket_addrs()?
            .next()
            .expect("Failed to parse address");

        let skel_builder = ProgSkelBuilder::default();
        let mut open_skel = skel_builder.open(open_obj)?;
        if log_enabled!(log::Level::Debug) {
            open_skel.progs.msg_verdict.set_log_level(1);
        }

        let ip4 = match address {
            SocketAddr::V4(addr) => Ok(u32::from_ne_bytes(addr.ip().octets())),
            _ => Err(Error::new(
                ErrorKind::InvalidInput,
                "Unsupported address family",
            )),
        }?;

        open_skel.maps.rodata_data.as_mut().unwrap().ip4 = ip4;
        open_skel.maps.rodata_data.as_mut().unwrap().port = address.port() as u32;

        let skel = open_skel.load()?;
        let sock_map_fd = skel.maps.sock_map.as_fd().as_raw_fd();

        let cgroup_fd = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open("/sys/fs/cgroup")?
            .into_raw_fd();

        let sockops = skel.progs.monitor_sockets.attach_cgroup(cgroup_fd)?;
        skel.progs.msg_verdict.attach_sockmap(sock_map_fd)?;

        debug!("Test program attached");

        Ok(Self { sockops, skel })
    }

    pub fn num_upgraded_conns(&self) -> Result<u32> {
        let func = &self.skel.progs.get_num_upgraded_conns;
        let input = libbpf_rs::ProgramInput::default();

        Ok(func.test_run(input)?.return_value)
    }

    pub fn get_match(&self, idx: usize) -> Result<Option<Vec<u8>>> {
        let id = self.skel.maps.matches.info()?.info.id;
        let map = MapHandle::from_map_id(id)?;

        let key = idx as u32;
        let key = unsafe { key.as_bytes() };
        Ok(map.lookup(&key, MapFlags::empty())?)
    }

    pub fn prog_fd(&self) -> i32 {
        self.skel.progs.msg_verdict.as_fd().as_raw_fd()
    }
}

pub struct OpenObject {
    inner: MaybeUninit<libbpf_rs::OpenObject>,
}

impl OpenObject {
    pub fn new() -> Self {
        Self {
            inner: MaybeUninit::uninit(),
        }
    }
}

impl Deref for OpenObject {
    type Target = MaybeUninit<libbpf_rs::OpenObject>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for OpenObject {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

unsafe impl Send for OpenObject {}
