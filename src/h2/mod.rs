#![allow(unused_imports)]

use crate::{bpf::TryIntoRawOctets, dfa::Action, h2::types::*};
use anyhow::Result;
use dfa::H2Dfa;
use libbpf_rs::{
    Link, PrintLevel, set_print,
    skel::{OpenSkel, SkelBuilder},
};
use log::{debug, info, log_enabled, warn};
use std::{
    mem::MaybeUninit,
    net::ToSocketAddrs,
    os::{
        fd::{AsFd, AsRawFd, IntoRawFd},
        unix::fs::OpenOptionsExt,
    },
};

mod dfa;

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/h2/parser.skel.rs"
));

fn print(level: PrintLevel, msg: String) {
    let msg = msg.trim_start_matches("libbpf:").trim();

    match level {
        PrintLevel::Debug => debug!(target: "libbpf", "{}", msg),
        PrintLevel::Info => info!(target: "libbpf", "{}", msg),
        PrintLevel::Warn => warn!(target: "libbpf", "{}", msg),
    }
}
fn new_transition(state: u16, action: Action, rodata: &rodata) -> trans {
    let action = match action {
        Action::StartCapture(mid) => rodata.a_start_capture | (mid as u16) & rodata.a_id_mask,
        Action::EndCapture(cid, mid) => {
            let id = (cid as u16) << 6 | (mid as u16);
            rodata.a_end_capture | id & rodata.a_id_mask
        }
        Action::Done => rodata.a_done,
        Action::None => 0,
    };

    trans { state, action }
}

fn inject_dfa(dfa: H2Dfa, skel: &mut OpenParserSkel) -> Result<()> {
    for (from, to, input, action) in dfa.iter_transitions() {
        let s = *from as usize;
        let data = skel.maps.rodata_data.as_mut().unwrap();
        let t = new_transition(*to, *action, data);
        data.s2ts[s][*input as usize] = t;
    }

    Ok(())
}

pub struct Parser<'obj> {
    skel: ParserSkel<'obj>,
    #[allow(dead_code)]
    sockops: Link,
}

unsafe impl<'obj> Send for Parser<'obj> {}

unsafe impl<'obj> Sync for Parser<'obj> {}

impl<'obj> Parser<'obj> {
    pub fn attach<A: ToSocketAddrs>(
        address: A,
        open_obj: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
    ) -> Result<Self> {
        set_print(Some((PrintLevel::Debug, print)));

        let address = address
            .to_socket_addrs()?
            .next()
            .expect("Failed to parse address");

        let skel_builder = ParserSkelBuilder::default();
        let mut open_skel = skel_builder.open(open_obj)?;
        if log_enabled!(log::Level::Debug) {
            open_skel.progs.msg_verdict.set_log_level(1);
        }

        let rodata = open_skel.maps.rodata_data.as_ref().unwrap();
        let mut dfa = H2Dfa::new(rodata.s_init, rodata.s_any);
        dfa.match_preface()?;

        inject_dfa(dfa, &mut open_skel)?;

        open_skel.maps.rodata_data.as_mut().unwrap().ip4 = address.try_into_ne_octets()?;
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

        debug!("eBPF http/2 attached");

        Ok(Self { sockops, skel })
    }
}
