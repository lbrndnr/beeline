use anyhow::Result;
use axum::{
    Router,
    body::Bytes,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
};
use beeline::h2::Parser;
use reqwest::Client;
use utils::{OpenObject, TestProgram};

mod utils;

const ECHO_ADDR: &str = "127.0.0.1:3000";

async fn echo(headers: HeaderMap, body: Bytes) -> Result<impl IntoResponse, StatusCode> {
    if let Ok(body) = String::from_utf8(body.to_vec()) {
        Ok((headers, body))
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}

async fn start_echo<A: tokio::net::ToSocketAddrs>(addr: A) -> Result<()> {
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

#[tokio::test]
async fn it_connects() {
    _ = env_logger::try_init();

    let mut open_obj = OpenObject::new();
    let server = start_echo(ECHO_ADDR).await;

    let mut parser = Parser::new(0, 1);
    parser.match_preface().expect("match_preface");

    let prog = TestProgram::attach(ECHO_ADDR, &mut open_obj, &parser).expect("attach");

    let client = Client::builder()
        .connection_verbose(true)
        .http2_prior_knowledge()
        .build()
        .expect("client");
    let resp = client
        .get("http://127.0.0.1:3000")
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    assert_eq!(prog.num_upgraded_conns().unwrap(), 1);

    drop(server);
    drop(prog);
}
