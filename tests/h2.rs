use anyhow::Result;
use axum::{
    Router,
    body::Bytes,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
};
use beeline::h2::Parser;
use std::{
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
};
use tokio::net::TcpStream;

const ECHO_ADDR: &str = "127.0.0.1:3000";

struct OpenObject {
    inner: MaybeUninit<libbpf_rs::OpenObject>,
}

impl OpenObject {
    pub fn new() -> Self {
        Self {
            inner: MaybeUninit::uninit(),
        }
    }
}

async fn echo(headers: HeaderMap, body: Bytes) -> Result<impl IntoResponse, StatusCode> {
    if let Ok(body) = String::from_utf8(body.to_vec()) {
        Ok((headers, body))
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}

async fn start_echo<'obj, A: tokio::net::ToSocketAddrs + std::net::ToSocketAddrs + Clone>(
    addr: A,
    open_obj: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
) -> Result<()> {
    let parser = Parser::attach(addr.clone(), open_obj);

    // build our application with a route
    let app = Router::new().route(
        "/",
        post(move |req_hdrs: HeaderMap, body: Bytes| {
            let res_hdrs = HeaderMap::new();
            echo(res_hdrs, body)
        }),
    );

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();

    Ok(())
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

#[tokio::test]
async fn it_connects() {
    let mut open_obj = OpenObject::new();
    let server = start_echo(ECHO_ADDR, &mut open_obj);
    let mut client = TcpStream::connect(ECHO_ADDR).await.unwrap();
}
