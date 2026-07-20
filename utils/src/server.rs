use std::net::SocketAddr;

use anyhow::Result;
use axum::{
    Router,
    body::Bytes,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
};
use tracing::debug;

async fn echo(headers: HeaderMap, body: Bytes) -> Result<impl IntoResponse, StatusCode> {
    if let Ok(body) = String::from_utf8(body.to_vec()) {
        debug!(
            "Received request with headers: {:?} and body: {}",
            headers, body
        );
        Ok((headers, body))
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}

/// Launches the echo server on the given address and returns the address it is
/// actually bound to. Pass an address with port `0` (e.g. `127.0.0.1:0`) to let
/// the OS assign a free ephemeral port, which avoids collisions between tests
/// running in parallel.
pub async fn launch<A: tokio::net::ToSocketAddrs>(addr: A) -> Result<SocketAddr> {
    let echo = get(move |hdrs: HeaderMap, body: Bytes| echo(hdrs, body));
    let app = Router::new()
        .route("/", echo.clone())
        .route("/{*path}", echo.clone());

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    Ok(local_addr)
}
