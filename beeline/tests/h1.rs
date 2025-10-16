use anyhow::Result;
use axum::{
    Router,
    body::Bytes,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
};
use beeline::h1::Parser;
use reqwest::Client;
use utils::test::{OpenObject, TestProgram};

const ECHO_ADDR: &str = "127.0.0.1:12345";

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
async fn it_matches_h2_preface() {
    _ = env_logger::try_init();

    let server = start_echo(ECHO_ADDR).await;

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(ECHO_ADDR, &mut open_obj).expect("attach");

    let mut parser = Parser::new();
    parser.match_preface().expect("match preface");

    let client = Client::builder()
        .http2_prior_knowledge()
        .build()
        .expect("client");
    let resp = client
        .get(format!("http://{}", ECHO_ADDR))
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    assert_eq!(prog.num_upgraded_conns().unwrap(), 1);

    drop(server);
    drop(prog);
}

#[tokio::test]
async fn it_parses_http_header() {
    // request with "user-agent: beeline"
}

#[tokio::test]
async fn it_parses_malformed_http_header() {
    // request with "UsEr-aGgEnT: beeline"

    // request with "user-agent   : beeline"

    // request with "user-agent:beeline"
}

#[tokio::test]
async fn it_parses_subsequent_http_headers() {}
