use anyhow::Result;
use axum::{
    Router,
    body::Bytes,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
};
use beeline::h2::Parser;
use httlib_huffman::encode;
use reqwest::{Client, header};
use utils::test::{OpenObject, TestProgram};

const ECHO_ADDR: &str = "127.0.0.1:12345";

fn assert_match_eq(prog: &TestProgram, idx: usize, expected: &str) {
    let mut expected_hf = Vec::new();
    encode(&expected.as_bytes(), &mut expected_hf).unwrap();

    assert_eq!(prog.get_match(idx).unwrap().unwrap(), expected_hf);
}

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
async fn parse_indexed_header_field() {
    _ = env_logger::try_init();

    let server = start_echo(ECHO_ADDR).await;

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(ECHO_ADDR, &mut open_obj).expect("attach");

    let mut parser = Parser::new();
    parser.capture_http_hdr("method").expect("match method");
    let parser = parser.attach(prog.prog_fd()).expect("attach parser");

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
    assert_match_eq(&prog, 0, "GET");

    drop(server);
    drop(prog);
    drop(parser);
}

#[tokio::test]
async fn parse_literal_header_field_no_indexing_indexed() {
    _ = env_logger::try_init();

    let server = start_echo(ECHO_ADDR).await;

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(ECHO_ADDR, &mut open_obj).expect("attach program");

    let mut parser = Parser::new();
    parser
        .capture_http_hdr("authorization")
        .expect("match authorization");
    let parser = parser.attach(prog.prog_fd()).expect("attach parser");

    let client = Client::builder()
        .http2_prior_knowledge()
        .build()
        .expect("client");
    let resp = client
        .get(format!("http://{}", ECHO_ADDR))
        .basic_auth("beeline", Some("beeline"))
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    assert_match_eq(&prog, 0, "Basic beeline:beeline");

    drop(server);
    drop(prog);
    drop(parser);
}

#[tokio::test]
async fn parse_literal_header_field_incremental_indexing_indexed() {
    _ = env_logger::try_init();

    let server = start_echo(ECHO_ADDR).await;

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(ECHO_ADDR, &mut open_obj).expect("attach program");

    let mut parser = Parser::new();
    parser
        .capture_http_hdr("user-agent")
        .expect("match user-agent");
    let parser = parser.attach(prog.prog_fd()).expect("attach parser");

    let client = Client::builder()
        .http2_prior_knowledge()
        .build()
        .expect("client");

    let user_agent = "beeline";
    let resp = client
        .get(format!("http://{}", ECHO_ADDR))
        .header(header::USER_AGENT, user_agent)
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    assert_match_eq(&prog, 0, user_agent);

    drop(server);
    drop(prog);
    drop(parser);
}

#[tokio::test]
async fn parse_literal_header_field_incremental_indexing_in_dynamic_table() {
    _ = env_logger::try_init();

    let server = start_echo(ECHO_ADDR).await;

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(ECHO_ADDR, &mut open_obj).expect("attach program");

    let mut parser = Parser::new();
    parser
        .capture_http_hdr("user-agent")
        .expect("match user-agent");

    parser
        .capture_http_hdr("accept-language")
        .expect("match accept-language");

    let parser = parser.attach(prog.prog_fd()).expect("attach parser");

    let client = Client::builder()
        .http2_prior_knowledge()
        .build()
        .expect("client");

    let user_agent = "beeline";
    let lang = "sumsum";
    let resp = client
        .get(format!("http://{}", ECHO_ADDR))
        .header(header::USER_AGENT, user_agent)
        .header(header::ACCEPT_LANGUAGE, lang)
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    assert_match_eq(&prog, 0, user_agent);
    assert_match_eq(&prog, 1, lang);

    // we repeat this request to check if the header has been added to the dynamic table
    let resp = client
        .get(format!("http://{}", ECHO_ADDR))
        .header(header::ACCEPT_LANGUAGE, lang)
        .header(header::USER_AGENT, user_agent)
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    assert_match_eq(&prog, 0, user_agent);
    assert_match_eq(&prog, 1, lang);

    drop(server);
    drop(prog);
    drop(parser);
}
