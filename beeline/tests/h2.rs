use std::net::SocketAddr;

use ::h2::{RecvStream, client};
use beeline::{h1, h2};
use bytes::Bytes;
use httlib_huffman as huffman;
use http::{HeaderValue, Request, Response, header};
use libbpf_rs::Link;
use tokio::net::TcpStream;
use utils::{
    server,
    test::{OpenObject, TestProgram},
};

fn assert_match_eq(prog: &TestProgram, idx: usize, expected: Option<&str>) {
    let actual_hf = prog.get_match(idx).expect("get_match");

    let mut actual = Vec::new();
    if let Some(actual_hf) = &actual_hf {
        huffman::decode(actual_hf, &mut actual, huffman::DecoderSpeed::OneBit).unwrap();
    }
    let actual = String::from_utf8(actual).unwrap();

    if expected.is_none() {
        assert!(
            actual_hf.is_none(),
            "get_match({idx}): {actual}, expected: none"
        );
    } else {
        let expected = expected.unwrap();
        assert!(
            actual_hf.is_some(),
            "get_match({idx}): none, expected: {expected}"
        );
        assert_eq!(actual.as_str(), expected);
    }
}

/// A minimal HTTP/2 client built directly on top of the `h2` crate, wrapping a single
/// connection so tests can issue several requests over it (e.g. to exercise the HPACK
/// dynamic table) and inspect the connection's own local/remote addresses.
struct Client {
    send_request: client::SendRequest<Bytes>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl Client {
    async fn connect(addr: SocketAddr, header_table_size: Option<u32>) -> Self {
        let stream = TcpStream::connect(addr).await.expect("connect");
        let local_addr = stream.local_addr().expect("local_addr");
        let remote_addr = stream.peer_addr().expect("peer_addr");

        let mut builder = client::Builder::new();
        if let Some(size) = header_table_size {
            builder.header_table_size(size);
        }

        let (send_request, connection) = builder
            .handshake::<_, Bytes>(stream)
            .await
            .expect("handshake");

        tokio::spawn(async move {
            connection.await.expect("connection");
        });

        Self {
            send_request,
            local_addr,
            remote_addr,
        }
    }

    async fn get(
        &self,
        uri: String,
        headers: &[(header::HeaderName, HeaderValue)],
    ) -> Response<RecvStream> {
        let mut req = Request::builder().method("GET").uri(uri);
        for (name, value) in headers {
            req = req.header(name, value);
        }
        let request = req.body(()).expect("build request");

        let mut send_request = self.send_request.clone().ready().await.expect("ready");
        let (response, _) = send_request
            .send_request(request, true)
            .expect("send_request");
        response.await.expect("response")
    }
}

fn attach_preface_parser(prog_fd: i32) -> (Vec<Link>, Option<Link>, Option<Link>) {
    h1::Parser::new()
        .match_preface()
        .expect("match preface")
        .replace_parse_msg("parse_h1")
        .replace_matched("matched_h1")
        .replace_extract("extract_h1_match")
        .attach(prog_fd)
        .expect("attach parser")
}

#[tokio::test]
async fn parse_indexed_header_field() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj).expect("attach");

    let h1 = attach_preface_parser(prog.prog_fd());
    let h2 = h2::Parser::new()
        .capture_http_hdr("method")
        .expect("match method")
        .replace_parse_msg("parse_h2")
        .replace_extract("extract_h2_match")
        .attach(prog.prog_fd())
        .expect("attach parser");

    let client = Client::connect(addr, None).await;
    let resp = client.get(format!("http://{}", addr), &[]).await;

    assert_eq!(resp.status(), 200);
    assert_match_eq(&prog, 0, Some("GET"));

    drop(prog);
    drop(h2);
    drop(h1);
}

#[tokio::test]
async fn parse_literal_header_field_no_indexing_indexed() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj).expect("attach program");

    let h1 = attach_preface_parser(prog.prog_fd());
    let h2 = h2::Parser::new()
        .capture_http_hdr("authorization")
        .expect("match authorization")
        .replace_parse_msg("parse_h2")
        .replace_extract("extract_h2_match")
        .attach(prog.prog_fd())
        .expect("attach parser");

    let client = Client::connect(addr, None).await;
    let auth = HeaderValue::from_static("Basic YmVlbGluZTpiZWVsaW5l"); // beeline:beeline in base64
    let resp = client
        .get(format!("http://{}", addr), &[(header::AUTHORIZATION, auth)])
        .await;

    assert_eq!(resp.status(), 200);
    assert_match_eq(&prog, 0, Some("Basic YmVlbGluZTpiZWVsaW5l"));

    drop(prog);
    drop(h2);
    drop(h1);
}

#[tokio::test]
async fn parse_literal_header_field_no_indexing_not_indexed() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj).expect("attach program");

    let h1 = attach_preface_parser(prog.prog_fd());
    let h2 = h2::Parser::new()
        .capture_http_hdr("sensitive")
        .expect("match sensitive")
        .replace_parse_msg("parse_h2")
        .replace_extract("extract_h2_match")
        .attach(prog.prog_fd())
        .expect("attach parser");

    let secret = "my secret";
    let mut val = HeaderValue::from_static(secret);
    val.set_sensitive(true);

    let client = Client::connect(addr, None).await;
    let resp = client
        .get(
            format!("http://{}", addr),
            &[(header::HeaderName::from_static("sensitive"), val)],
        )
        .await;

    assert_eq!(resp.status(), 200);
    assert_match_eq(&prog, 0, Some(secret));

    drop(prog);
    drop(h2);
    drop(h1);
}

#[tokio::test]
async fn parse_literal_header_field_incremental_indexing_indexed() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj).expect("attach program");

    let h1 = attach_preface_parser(prog.prog_fd());
    let h2 = h2::Parser::new()
        .capture_http_hdr("user-agent")
        .expect("match user-agent")
        .capture_http_hdr("path")
        .expect("match path")
        .replace_parse_msg("parse_h2")
        .replace_extract("extract_h2_match")
        .attach(prog.prog_fd())
        .expect("attach parser");

    let client = Client::connect(addr, None).await;
    let user_agent = "beeline";
    let path = "/bee/1234";
    let resp = client
        .get(
            format!("http://{}{}", addr, path),
            &[(header::USER_AGENT, HeaderValue::from_static(user_agent))],
        )
        .await;

    assert_eq!(resp.status(), 200);
    assert_match_eq(&prog, 0, Some(user_agent));
    assert_match_eq(&prog, 1, Some(path));

    drop(prog);
    drop(h2);
    drop(h1);
}

#[tokio::test]
async fn parse_literal_header_field_incremental_indexing_in_dynamic_table() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj).expect("attach program");

    let h1 = attach_preface_parser(prog.prog_fd());
    let h2 = h2::Parser::new()
        .capture_http_hdr("user-agent")
        .expect("match user-agent")
        .capture_http_hdr("accept-language")
        .expect("match accept-language")
        .replace_parse_msg("parse_h2")
        .replace_extract("extract_h2_match")
        .attach(prog.prog_fd())
        .expect("attach parser");

    let client = Client::connect(addr, None).await;
    let user_agent = "beeline";
    let lang = "sumsum";
    let resp = client
        .get(
            format!("http://{}", addr),
            &[
                (header::USER_AGENT, HeaderValue::from_static(user_agent)),
                (header::ACCEPT_LANGUAGE, HeaderValue::from_static(lang)),
            ],
        )
        .await;

    assert_eq!(resp.status(), 200);
    assert_match_eq(&prog, 0, Some(user_agent));
    assert_match_eq(&prog, 1, Some(lang));

    // repeat the request with other headers
    // this will check if it indexes the dynamic table correctly
    let resp = client
        .get(
            format!("http://{}", addr),
            &[(header::VIA, HeaderValue::from_static("the hive"))],
        )
        .await;

    assert_eq!(resp.status(), 200);
    assert_match_eq(&prog, 0, None);
    assert_match_eq(&prog, 1, None);

    // we repeat this request to check if the header has been added to the dynamic table
    let resp = client
        .get(
            format!("http://{}", addr),
            &[
                (header::ACCEPT_LANGUAGE, HeaderValue::from_static(lang)),
                (header::USER_AGENT, HeaderValue::from_static(user_agent)),
            ],
        )
        .await;

    assert_eq!(resp.status(), 200);
    assert_match_eq(&prog, 0, Some(user_agent));
    assert_match_eq(&prog, 1, Some(lang));

    drop(prog);
    drop(h2);
    drop(h1);
}

#[tokio::test]
async fn update_dynamic_table_size() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj).expect("attach program");

    let h1 = attach_preface_parser(prog.prog_fd());
    let h2 = h2::Parser::new()
        .replace_parse_msg("parse_h2")
        .attach(prog.prog_fd())
        .expect("attach parser");

    let client = Client::connect(addr, Some(1234)).await;

    let resp = client.get(format!("http://{}", addr), &[]).await;

    assert_eq!(resp.status(), 200);

    let max_size = h2
        .max_dynamic_table_size(client.local_addr, client.remote_addr)
        .expect("max_dynamic_table_size")
        .expect("dynamic table state recorded for connection");

    assert_eq!(max_size, 1234);

    drop(prog);
    drop(h2);
    drop(h1);
}

// #[tokio::test]
// async fn evict_header_field_from_dynamic_table() {
//     tracing_subscriber::fmt()
// .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
// .try_init().expect("init tracing");

//     let server = server::launch().await;

//     let mut open_obj = OpenObject::new();
//     let prog = TestProgram::attach(addr, &mut open_obj).expect("attach program");

//     let h1 = h1::Parser::new()
//         .match_preface()
//         .expect("match preface")
//         .replace_parse_msg("parse_h1")
//         .replace_matched("matched_h1")
//         .replace_extract("extract_h1_match")
//         .attach(prog.prog_fd())
//         .expect("attach parser");

//     let h2 = h2::Parser::new()
//         .capture_http_hdr("user-agent")
//         .expect("match user-agent")
//         .capture_http_hdr("accept-language")
//         .expect("match accept-language")
//         .replace_parse_msg("parse_h2")
//         .replace_extract("extract_h2_match")
//         .attach(prog.prog_fd())
//         .expect("attach parser");

//     let client = Client::connect(addr, None).await;
//     let user_agent = "beeline";
//     let lang = "sumsum";
//     let resp = client
//         .get(format!("http://{}", addr))
//         .header(header::USER_AGENT, user_agent)
//         .header(header::ACCEPT_LANGUAGE, lang)
//         .send()
//         .await
//         .expect("request");

//     assert_eq!(resp.status(), 200);
//     assert_match_eq(&prog, 0, Some(user_agent));
//     assert_match_eq(&prog, 1, Some(lang));

// //     drop(prog);
//     drop(h2);
//     drop(h1);
// }
