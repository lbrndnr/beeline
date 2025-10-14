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
use utils::test::{OpenObject, TestProgram};

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
async fn it_upgrades_to_h2() {
    _ = env_logger::try_init();

    let server = start_echo(ECHO_ADDR).await;

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(ECHO_ADDR, &mut open_obj).expect("attach");

    let mut parser = Parser::new();
    // parser.match_preface().expect("match preface");

    let client = Client::builder()
        .connection_verbose(true)
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
async fn it_parses_indexed_header_field() {
    _ = env_logger::try_init();

    let server = start_echo(ECHO_ADDR).await;

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(ECHO_ADDR, &mut open_obj).expect("attach");

    let mut parser = Parser::new();
    // parser.match_preface().expect("match preface");
    parser.match_http_hdr("method").expect("match method");
    let parser = parser.attach(prog.prog_fd()).expect("attach parser");

    let client = Client::builder()
        .connection_verbose(true)
        .http2_prior_knowledge()
        .build()
        .expect("client");
    let resp = client
        .get(format!("http://{}", ECHO_ADDR))
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    assert_eq!(
        prog.get_match(0)
            .unwrap()
            .unwrap()
            .iter()
            .take(3)
            .copied()
            .collect::<Vec<u8>>(),
        vec![197, 131, 127] // "get" huffman encoded
    );

    drop(server);
    drop(prog);
    drop(parser);
}

#[tokio::test]
async fn it_parses_new_literal_header_field() {
    _ = env_logger::try_init();

    let server = start_echo(ECHO_ADDR).await;

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(ECHO_ADDR, &mut open_obj).expect("attach program");

    let mut parser = Parser::new();
    // parser.match_preface().expect("match preface");
    parser
        .match_http_hdr("user-agent")
        .expect("match user-agent");
    let parser = parser.attach(prog.prog_fd()).expect("attach parser");

    let client = Client::builder()
        .connection_verbose(true)
        .http2_prior_knowledge()
        .build()
        .expect("client");
    let resp = client
        .get(format!("http://{}", ECHO_ADDR))
        .header("user-agent", "beeline")
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    assert_eq!(
        prog.get_match(0)
            .unwrap()
            .unwrap()
            .iter()
            .take(5)
            .copied()
            .collect::<Vec<u8>>(),
        vec![140, 165, 160, 213, 23] // "beeline" huffman encoded
    );

    drop(server);
    drop(prog);
    drop(parser);
}
