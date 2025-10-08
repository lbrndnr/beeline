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

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/prog.skel"));

fn new_transition(state: u16, action: Action, rodata: &rodata) -> trans {
    let action = match action {
        Action::CaptureFieldValue(cid) => rodata.a_start_capture | (cid as u16) & rodata.a_id_mask,
        // Action::EndCapturing(rid) => rodata.a_end_capture | (rid as u16) & rodata.a_id_mask,
        Action::Done => rodata.a_done,
        Action::None => 0,
    };

    trans { state, action }
}

fn inject_parser(parser: &Parser, skel: &mut OpenProgSkel) -> Result<()> {
    for (from, to, input, action) in parser.iter_transitions() {
        let s = *from as usize;
        let data = skel.maps.rodata_data.as_mut().unwrap();
        let t = new_transition(*to, *action, data);
        println!(
            "Transition from state {} to state {} on input {} with action {:?}",
            from, to, input, action
        );
        data.s2ts[s][*input as usize] = t;
    }

    Ok(())
}

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
        parser: &Parser,
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

        inject_parser(parser, &mut open_skel)?;

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

        let id = skel.maps.static_table.info()?.info.id;
        let static_table = MapHandle::from_map_id(id)?;
        let key = unsafe { 2.as_bytes() };

        let mut val = vec![0u8; 64];
        val[0] = 0xa4;
        val[1] = 0xa9;
        val[2] = 0x9c;
        val[3] = 0xf2;
        val[4] = 0x7f;
        val[5] = 0xc5;
        val[6] = 0x83;
        val[7] = 0x7f;

        static_table.update(&key, &val, MapFlags::ANY)?;

        debug!("eBPF http/2 attached");

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
