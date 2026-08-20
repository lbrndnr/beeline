//! A static file server whose requests can be answered from the kernel.
//!
//! The server itself is an ordinary axum application. Started with
//! `--with-ebpf`, [`fastpath::Server`] attaches a Beeline parser to its sockets,
//! which answers the requests for the files listed in `routes` before they ever
//! reach user space. Without it no eBPF is loaded at all and every request is
//! answered the ordinary way, which is what the two are worth comparing.

use axum::http::StatusCode;
use clap::Parser;
use example::{h2serve, listener::BeelineListener};
use fastpath::Server;
use std::{collections::HashMap, net::SocketAddr, path::PathBuf};
use tokio::net::TcpListener;
use tower_http::{
    services::{ServeDir, ServeFile},
    set_status::SetStatus,
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use xbpf::OpenObject;

mod fastpath;

/// A static file server that can answer its smaller assets from eBPF.
#[derive(Parser)]
#[command(about, long_about = None)]
struct Args {
    /// Attach the eBPF fast path, so that the assets that fit its routing table
    /// are answered in the kernel. Without it the server loads no eBPF at all.
    #[arg(long)]
    with_ebpf: bool,

    /// The address to listen on.
    #[arg(long, default_value = "127.0.0.1:8080")]
    addr: SocketAddr,
}

/// Every asset the page is made of, offered to the fast path as a whole.
///
/// The images are far too large for its routing table and it says so and
/// declines them, see [`Server::attach`]; which of these end up answered in the
/// kernel is its decision to make rather than one to second guess here.
fn fastpath_routes(assets_dir: &str) -> HashMap<String, PathBuf> {
    [
        "/index.html",
        "/style.css",
        "/script.js",
        "/honeycomb.png",
        "/rings.png",
        "/stripes.png",
    ]
    .into_iter()
    .map(|path| {
        let file = PathBuf::from(format!("{assets_dir}{path}"));
        (path.to_string(), file)
    })
    .collect()
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!(
                    "{}=debug,bpf=trace,tower_http=debug",
                    env!("CARGO_CRATE_NAME")
                )
                .into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let assets_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/assets");
    let index_html = SetStatus::new(
        ServeFile::new(format!("{assets_dir}/index.html")),
        StatusCode::NOT_FOUND,
    );
    let serve_dir = ServeDir::new(assets_dir).not_found_service(index_html);

    let app = axum::Router::new()
        .fallback_service(serve_dir)
        .layer(TraceLayer::new_for_http());

    // the fast path has to outlive the server, and nothing of it is loaded
    // unless it was asked for
    let mut open_obj = OpenObject::new();
    let _fastpath = if args.with_ebpf {
        let routes = fastpath_routes(assets_dir);
        Some(Server::attach(args.addr, &mut open_obj, routes).expect("attach"))
    } else {
        tracing::info!("Running without the eBPF fast path, pass --with-ebpf to attach it");
        None
    };

    let listener = TcpListener::bind(args.addr).await.unwrap();
    let listener = BeelineListener::new(listener);
    tracing::debug!("listening on {}", listener.local_addr().unwrap());

    h2serve::serve(listener, app).await;
}
