use beeline::h1;
use http::{HeaderName, HeaderValue, header};
use reqwest::Client;
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use utils::{
    server,
    test::{Direction, OpenObject, TestProgram},
};

fn assert_match_eq(prog: &TestProgram, idx: usize, expected: Option<&HeaderValue>) {
    let actual = prog.get_match(idx).expect("get_match");
    let actual = actual.map(|s| String::from_utf8(s).unwrap());

    if expected.is_none() {
        assert!(
            actual.is_none(),
            "get_match({idx}): {}, expected: none",
            actual.unwrap()
        );
    } else {
        let expected = expected.unwrap().to_str().unwrap();
        assert!(
            actual.is_some(),
            "get_match({idx}): none, expected: {expected}"
        );
        assert_eq!(actual.unwrap().as_str(), expected);
    }
}

fn build_client() -> Client {
    Client::builder().build().expect("client")
}

/// Writes `req` to a raw connection to `addr` and returns the response it reads back.
async fn send_raw(addr: SocketAddr, req: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(req.as_bytes())
        .await
        .expect("write request");

    let mut buf = [0; 1024];
    let len = stream.read(&mut buf).await.expect("read response");

    String::from_utf8_lossy(&buf[..len]).into_owned()
}

fn attach_h1_parser(prog_fd: i32, match_preface: bool, hdrs: &[HeaderName]) -> h1::AttachedParser {
    let mut h1 = h1::Parser::new();
    if match_preface {
        h1 = h1.match_h2_preface();
    }
    for hdr in hdrs {
        h1 = h1.capture_hdr(hdr);
    }

    h1.replace_parse_msg("parse_h1")
        .replace_matched("matched_h1")
        .replace_extract("extract_h1_match")
        .attach(prog_fd)
        .expect("attach parser")
}

#[tokio::test]
async fn match_h2_preface() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach");

    let _h1 = attach_h1_parser(prog.prog_fd(), true, &[]);
    let client = Client::builder()
        .http2_prior_knowledge()
        .build()
        .expect("client");
    let resp = client
        .get(format!("http://{}", addr))
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    assert_eq!(prog.num_upgraded_conns().unwrap(), 1);
}

#[tokio::test]
async fn parse_simple_header() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach");
    let _h1 = attach_h1_parser(prog.prog_fd(), true, &[header::USER_AGENT]);

    let user_agent = HeaderValue::from_static("some user agent");
    let client = build_client();
    let resp = client
        .get(format!("http://{}", addr))
        .header(header::USER_AGENT, user_agent.clone())
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    assert_match_eq(&prog, 1, Some(&user_agent));
}

#[tokio::test]
async fn ignore_header_case() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach");
    let _h1 = attach_h1_parser(prog.prog_fd(), true, &[header::USER_AGENT]);

    // reqwest normalizes header names, so the request is written to the socket as is
    let user_agent = HeaderValue::from_static("beeline");
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {addr}\r\nUsEr-aGEnT: {}\r\n\r\n",
        user_agent.to_str().unwrap()
    );

    let resp = send_raw(addr, &req).await;

    assert!(
        resp.starts_with("HTTP/1.1 200 OK"),
        "unexpected response: {resp}"
    );
    assert_match_eq(&prog, 1, Some(&user_agent));
}

#[tokio::test]
async fn ignores_header_whitespace() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach");
    let _h1 = attach_h1_parser(prog.prog_fd(), true, &[header::USER_AGENT]);

    // the whitespace between the colon and the value is not part of the value
    let user_agent = HeaderValue::from_static("beeline");
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {addr}\r\nuser-agent:  \t{}\r\n\r\n",
        user_agent.to_str().unwrap()
    );

    let resp = send_raw(addr, &req).await;

    assert!(
        resp.starts_with("HTTP/1.1 200 OK"),
        "unexpected response: {resp}"
    );
    assert_match_eq(&prog, 1, Some(&user_agent));

    // beeline also matches whitespace between the name and the colon. the server
    // rejects such a request as a smuggling risk, but it is parsed off the wire
    // before it ever gets there, so its status is of no interest here
    let user_agent = HeaderValue::from_static("sumsum");
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {addr}\r\nuser-agent \t:  {}\r\n\r\n",
        user_agent.to_str().unwrap()
    );

    _ = send_raw(addr, &req).await;

    assert_match_eq(&prog, 1, Some(&user_agent));
}

#[tokio::test]
async fn parse_subsequent_headers() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach");

    let _h1 = attach_h1_parser(
        prog.prog_fd(),
        true,
        &[header::USER_AGENT, header::ACCEPT_LANGUAGE],
    );

    let client = build_client();
    let user_agent = HeaderValue::from_static("beeline");
    let lang = HeaderValue::from_static("sumsum");
    let resp = client
        .get(format!("http://{}", addr))
        .header(header::USER_AGENT, user_agent.clone())
        .header(header::ACCEPT_LANGUAGE, lang.clone())
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    assert_match_eq(&prog, 1, Some(&user_agent));
    assert_match_eq(&prog, 2, Some(&lang));
}

#[tokio::test]
async fn parse_status_line_only() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach");

    let _h1 = attach_h1_parser(
        prog.prog_fd(),
        true,
        &[beeline::header::PATH, beeline::header::METHOD],
    );

    let client = build_client();
    let resp = client
        .get(format!("http://{}", addr))
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    let method = HeaderValue::from_static("GET");
    let path = HeaderValue::from_static("/");
    assert_match_eq(&prog, 1, Some(&path));
    assert_match_eq(&prog, 2, Some(&method));
}

#[tokio::test]
async fn parse_status_line_and_subsequent_header() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach");

    let _h1 = attach_h1_parser(
        prog.prog_fd(),
        true,
        &[beeline::header::PATH, header::CONTENT_LENGTH],
    );

    let body = "Hello, world!";
    let client = build_client();
    let resp = client
        .get(format!("http://{}", addr))
        .body(body)
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    let path = HeaderValue::from_static("/");
    let content_length = HeaderValue::from_str(&format!("{}", body.len())).unwrap();
    assert_match_eq(&prog, 1, Some(&path));
    assert_match_eq(&prog, 2, Some(&content_length));
}

#[tokio::test]
async fn parse_status_code() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj, Direction::Upstream).expect("attach");

    let _h1 = attach_h1_parser(
        prog.prog_fd(),
        true,
        &[beeline::header::STATUS, header::CONTENT_LENGTH],
    );

    let body = "Hello, world!";
    let client = build_client();
    let resp = client
        .get(format!("http://{}", addr))
        .body(body)
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    let status = HeaderValue::from_static("200");
    let content_length = HeaderValue::from_str(&format!("{}", body.len())).unwrap();
    assert_match_eq(&prog, 1, Some(&status));
    assert_match_eq(&prog, 2, Some(&content_length));
}
