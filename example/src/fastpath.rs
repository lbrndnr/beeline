#![allow(unused_imports)]

use anyhow::{Context, Result, bail};
use as_bytes::AsBytes;
use axum::http;
use beeline::{h1, h2};
use httlib_huffman as huffman;
use std::{
    collections::HashMap,
    io::{Error, ErrorKind},
    mem::MaybeUninit,
    net::{SocketAddr, ToSocketAddrs},
    ops::{Deref, DerefMut},
    os::{
        fd::{AsFd, AsRawFd, IntoRawFd},
        unix::fs::OpenOptionsExt,
    },
    path::Path,
};
use tracing::{Level, debug, info, warn};
use types::*;
use xbpf::{
    OpenObject,
    libbpf::{
        self as libbpf_rs, Link, MapCore, MapFlags, MapHandle, MapType,
        skel::{OpenSkel, Skel, SkelBuilder},
    },
};

xbpf::include_bpf!("server");

// Must stay in sync with the corresponding `#define`s in server.bpf.c.
const MAX_ROUTES: usize = 16;
const MAX_ROUTE_PATH: usize = 64;
const MAX_ROUTE_BODY: usize = 4096;

pub struct Server<'obj> {
    #[allow(dead_code)]
    skel: ServerSkel<'obj>,
    #[allow(dead_code)]
    sockops: Link,
    #[allow(dead_code)]
    h1: h1::AttachedParser,
}

unsafe impl<'obj> Send for Server<'obj> {}

unsafe impl<'obj> Sync for Server<'obj> {}

fn content_type(file: &Path) -> &'static str {
    match file.extension().and_then(|ext| ext.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "application/javascript",
        Some("css") => "text/css",
        Some("json") => "application/json",
        _ => "application/octet-stream",
    }
}

/// Renders the full HTTP/1.1 response (status line, headers and body) that
/// the fast path will serve verbatim whenever `path` is requested.
fn render_response(file: &Path) -> Result<Vec<u8>> {
    let body = std::fs::read(file)
        .with_context(|| format!("failed to read fastpath asset {}", file.display()))?;

    let mut resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: keep-alive\r\n\r\n",
        body.len(),
        content_type(file),
    )
    .into_bytes();
    resp.extend_from_slice(&body);

    Ok(resp)
}

impl<'obj> Server<'obj> {
    /// Attaches the server's fast path.
    ///
    /// `routes` maps request paths (e.g. `/index.html`) to files on disk. The
    /// contents of those files are pre-rendered into full HTTP responses and
    /// loaded into the eBPF program's `.bss` section, so that requests for a
    /// matching path can be served directly from the fast path without ever
    /// reaching userspace.
    pub fn attach<A: ToSocketAddrs>(
        address: A,
        open_obj: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
        routes: HashMap<String, std::path::PathBuf>,
    ) -> Result<Self> {
        if routes.len() > MAX_ROUTES {
            bail!(
                "too many fastpath routes: {} configured, at most {MAX_ROUTES} supported",
                routes.len()
            );
        }

        let mut prepared = Vec::with_capacity(routes.len());
        for (path, file) in routes.iter() {
            let key = path.as_bytes().to_vec();
            if key.len() > MAX_ROUTE_PATH {
                bail!("fastpath route path `{path}` is longer than {MAX_ROUTE_PATH} bytes");
            }

            let body = render_response(file)?;
            if body.len() > MAX_ROUTE_BODY {
                bail!("fastpath response for `{path}` is longer than {MAX_ROUTE_BODY} bytes");
            }

            prepared.push((key, body));
        }

        let address = address
            .to_socket_addrs()?
            .next()
            .expect("Failed to parse address");

        let skel_builder = ServerSkelBuilder::default();
        let mut open_skel = skel_builder.open(open_obj)?;
        if tracing::event_enabled!(Level::TRACE) {
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

        let bss = open_skel.maps.bss_data.as_mut().unwrap();
        for (i, (_, body)) in prepared.iter().enumerate() {
            let route = &mut bss.routes[i];
            route.body[..body.len()].copy_from_slice(body);
            route.body_len = body.len() as u32;
        }

        let skel = open_skel.load()?;
        _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .try_init();
        xbpf::tracing::try_init(skel.object())?;

        // the route index is a hash map, so it can only be populated once the
        // program is loaded and the map created
        for (i, (key, ..)) in prepared.iter().enumerate() {
            let mut padded = [0; MAX_ROUTE_PATH];
            padded[..key.len()].copy_from_slice(key);

            skel.maps
                .route_idx
                .update(&padded, &[i as u8], MapFlags::ANY)
                .with_context(|| format!("failed to index fastpath route {i}"))?;
        }
        let sock_map_fd = skel.maps.sock_map.as_fd().as_raw_fd();
        let prog_fd = skel.progs.msg_verdict.as_fd().as_raw_fd();

        let h1 = h1::Parser::new()
            .capture_hdr(&beeline::header::PATH)
            .capture_hdr(&http::header::CONTENT_LENGTH)
            .replace_parse_msg("parse_h1")
            .replace_extract("extract_h1_match")
            .attach(prog_fd)?;

        let cgroup_fd = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open("/sys/fs/cgroup")?
            .into_raw_fd();

        let sockops = skel.progs.monitor_sockets.attach_cgroup(cgroup_fd)?;
        skel.progs.msg_verdict.attach_sockmap(sock_map_fd)?;

        debug!("Server fast path attached");

        Ok(Self { sockops, skel, h1 })
    }
}
