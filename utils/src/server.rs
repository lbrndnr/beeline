use anyhow::Result;
use axum::{
    Router,
    body::Bytes,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    routing::post,
};
use tokio::task::JoinHandle;

async fn echo(headers: HeaderMap, body: Bytes) -> Result<impl IntoResponse, StatusCode> {
    if let Ok(body) = String::from_utf8(body.to_vec()) {
        Ok((headers, body))
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}

pub async fn launch<A: tokio::net::ToSocketAddrs>(addr: A) -> Result<()> {
    let app = Router::new().route(
        "/",
        get(move |_: HeaderMap, body: Bytes| {
            let res_hdrs = HeaderMap::new();
            echo(res_hdrs, body)
        }),
    );

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    Ok(())
}

pub async fn launch_cancellable<A: tokio::net::ToSocketAddrs>(addr: A) -> Result<JoinHandle<()>> {
    let app = Router::new()
        .route(
            "/{*path}",
            get(move |_: HeaderMap, body: Bytes| {
                let res_hdrs = HeaderMap::new();
                echo(res_hdrs, body)
            }),
        )
        .route(
            "/",
            get(move |_: HeaderMap, body: Bytes| {
                let res_hdrs = HeaderMap::new();
                echo(res_hdrs, body)
            }),
        )
        .route(
            "/{*path}",
            post(move |_: HeaderMap, body: Bytes| {
                let res_hdrs = HeaderMap::new();
                echo(res_hdrs, body)
            }),
        )
        .route(
            "/",
            post(move |_: HeaderMap, body: Bytes| {
                let res_hdrs = HeaderMap::new();
                echo(res_hdrs, body)
            }),
        );

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    Ok(handle)
}
