//! A static file server whose requests are answered from the kernel.
//!
//! The server itself is an ordinary axum application. [`fastpath::Server`]
//! attaches a Beeline parser to its sockets, which answers the requests for the
//! files listed in `routes` before they ever reach user space.

use axum::http::StatusCode;
use fastpath::{OpenObject, Server};
use std::{collections::HashMap, net::SocketAddr, path::PathBuf};
use tokio::net::TcpListener;
use tower_http::{
    services::{ServeDir, ServeFile},
    set_status::SetStatus,
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod fastpath;

#[tokio::main]
async fn main() {
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

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));

    let routes = HashMap::from([
        (
            "/index.html".to_string(),
            PathBuf::from(format!("{assets_dir}/index.html")),
        ),
        (
            "/script.js".to_string(),
            PathBuf::from(format!("{assets_dir}/script.js")),
        ),
    ]);

    let mut open_obj = OpenObject::new();
    let fastpath = Server::attach(addr, &mut open_obj, routes).expect("attach");

    let listener = TcpListener::bind(addr).await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();

    drop(fastpath);
}
