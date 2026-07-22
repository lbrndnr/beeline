use std::net::SocketAddr;

use ::h2::{RecvStream, client};
use beeline::{
    h1,
    h2::{self, AttachedParser},
};
use bytes::Bytes;
use httlib_huffman as huffman;
use http::{HeaderName, HeaderValue, Request, Response, header};
use libbpf_rs::Link;
use tokio::net::TcpStream;
use utils::{
    server,
    test::{OpenObject, TestProgram},
};

const TEST_HEADER: &str = "testheader";

fn huffman_encode(val: &str) -> Vec<u8> {
    let mut res = Vec::new();
    huffman::encode(val.as_bytes(), &mut res).unwrap();
    res
}

fn huffman_decode(val: &[u8]) -> String {
    let mut res = Vec::new();
    huffman::decode(val, &mut res, huffman::DecoderSpeed::OneBit).unwrap();
    String::from_utf8(res).unwrap()
}

fn assert_match_eq(prog: &TestProgram, idx: usize, expected: Option<&str>) {
    let actual_hf = prog.get_match(idx).expect("get_match");
    let actual = actual_hf.map(|val| huffman_decode(&val));

    if expected.is_none() {
        assert!(
            actual.is_none(),
            "get_match({idx}): {}, expected: none",
            actual.unwrap()
        );
    } else {
        let expected = expected.unwrap();
        assert!(
            actual.is_some(),
            "get_match({idx}): none, expected: {expected}"
        );
        assert_eq!(actual.unwrap().as_str(), expected);
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

    #[allow(unused_results)]
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
        let response = response.await.expect("response");

        assert!(response.status().is_success());

        response
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

fn attach_h2_parser(prog_fd: i32, hdrs: &[&str]) -> AttachedParser {
    let mut h2 = h2::Parser::new();
    for hdr in hdrs {
        h2 = h2.capture_http_hdr(hdr).expect("capture {hdr}");
    }

    h2.replace_parse_msg("parse_h2")
        .replace_extract("extract_h2_match")
        .attach(prog_fd)
        .expect("attach parser")
}

#[tokio::test]
async fn parse_header_field_indexed_in_static_table() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj).expect("attach");

    let h1 = attach_preface_parser(prog.prog_fd());
    let h2 = attach_h2_parser(prog.prog_fd(), &["method"]);

    let client = Client::connect(addr, None).await;
    client.get(format!("http://{}", addr), &[]).await;

    assert_match_eq(&prog, 0, Some("GET"));

    drop(prog);
    drop(h2);
    drop(h1);
}

#[tokio::test]
async fn parse_header_field_no_indexing_name_indexed_in_static_table() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj).expect("attach program");

    let h1 = attach_preface_parser(prog.prog_fd());
    let h2 = attach_h2_parser(prog.prog_fd(), &["authorization"]);

    let client = Client::connect(addr, None).await;
    let auth = HeaderValue::from_static("Basic YmVlbGluZTpiZWVsaW5l"); // beeline:beeline in base64
    client
        .get(format!("http://{}", addr), &[(header::AUTHORIZATION, auth)])
        .await;

    assert_match_eq(&prog, 0, Some("Basic YmVlbGluZTpiZWVsaW5l"));

    drop(prog);
    drop(h2);
    drop(h1);
}

#[tokio::test]
async fn parse_header_field_never_indexing_name_indexed_in_static_table() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj).expect("attach program");

    let h1 = attach_preface_parser(prog.prog_fd());
    let h2 = attach_h2_parser(prog.prog_fd(), &["sensitive"]);

    let secret = "my secret";
    let mut val = HeaderValue::from_static(secret);
    val.set_sensitive(true);

    let client = Client::connect(addr, None).await;
    client
        .get(
            format!("http://{}", addr),
            &[(header::HeaderName::from_static("sensitive"), val)],
        )
        .await;

    assert_match_eq(&prog, 0, Some(secret));

    drop(prog);
    drop(h2);
    drop(h1);
}

#[tokio::test]
async fn parse_header_field_incremental_indexing_name_indexed_in_static_table() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj).expect("attach program");

    let h1 = attach_preface_parser(prog.prog_fd());
    let h2 = attach_h2_parser(prog.prog_fd(), &["user-agent", "path"]);

    let client = Client::connect(addr, None).await;
    let user_agent = "beeline";
    let path = "/bee/1234";

    client
        .get(
            format!("http://{}{}", addr, path),
            &[(header::USER_AGENT, HeaderValue::from_static(user_agent))],
        )
        .await;
    assert_match_eq(&prog, 0, Some(user_agent));
    assert_match_eq(&prog, 1, Some(path));

    drop(prog);
    drop(h2);
    drop(h1);
}

// #[tokio::test]
// async fn parse_header_field_incremental_indexing_new_name() {
//     let addr = server::launch().await.expect("launch server");

//     let mut open_obj = OpenObject::new();
//     let prog = TestProgram::attach(addr, &mut open_obj).expect("attach program");

//     let h1 = attach_preface_parser(prog.prog_fd());
//     let h2 = attach_h2_parser(prog.prog_fd(), &[TEST_HEADER, "path"]);

//     let client = Client::connect(addr, None).await;
//     let hdr = "beeline";
//     let path = "/bee/1234";

//     client
//         .get(
//             format!("http://{}{}", addr, path),
//             &[(
//                 HeaderName::from_static(TEST_HEADER),
//                 HeaderValue::from_static(hdr),
//             )],
//         )
//         .await;
//     assert_match_eq(&prog, 0, Some(hdr));
//     assert_match_eq(&prog, 1, Some(path));

//     drop(prog);
//     drop(h2);
//     drop(h1);
// }

#[tokio::test]
async fn parse_header_field_incremental_indexing_indexed_in_dynamic_table() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj).expect("attach program");

    let h1 = attach_preface_parser(prog.prog_fd());
    let h2 = attach_h2_parser(prog.prog_fd(), &["user-agent", "accept-language"]);

    let client = Client::connect(addr, None).await;
    let user_agent = "beeline";
    let lang = "sumsum";
    client
        .get(
            format!("http://{}", addr),
            &[
                (header::USER_AGENT, HeaderValue::from_static(user_agent)),
                (header::ACCEPT_LANGUAGE, HeaderValue::from_static(lang)),
            ],
        )
        .await;
    assert_match_eq(&prog, 0, Some(user_agent));
    assert_match_eq(&prog, 1, Some(lang));

    // repeat the request with other headers
    // this will check if it indexes the dynamic table correctly
    client
        .get(
            format!("http://{}", addr),
            &[(header::VIA, HeaderValue::from_static("the hive"))],
        )
        .await;
    assert_match_eq(&prog, 0, None);
    assert_match_eq(&prog, 1, None);

    // we repeat this request to check if the header has been added to the dynamic table
    client
        .get(
            format!("http://{}", addr),
            &[
                (header::ACCEPT_LANGUAGE, HeaderValue::from_static(lang)),
                (header::USER_AGENT, HeaderValue::from_static(user_agent)),
            ],
        )
        .await;
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
    let h2 = attach_h2_parser(prog.prog_fd(), &[]);

    let client = Client::connect(addr, Some(1234)).await;
    client.get(format!("http://{}", addr), &[]).await;

    let max_size = h2
        .dynamic_table_info(client.local_addr, client.remote_addr)
        .expect("dynamic_table_info")
        .max_size;
    assert_eq!(max_size, 1234);

    drop(prog);
    drop(h2);
    drop(h1);
}

// #[tokio::test]
// async fn evict_header_field_from_dynamic_table() {
//     let addr = server::launch().await.expect("launch server");

//     let mut open_obj = OpenObject::new();
//     let prog = TestProgram::attach(addr, &mut open_obj).expect("attach program");

//     let h1 = attach_preface_parser(prog.prog_fd());
//     let h2 = attach_h2_parser(prog.prog_fd(), &[TEST_HEADER]);

//     let hdr = "asdfqwer";

//     let client = Client::connect(addr, Some(128)).await;
//     client
//         .get(
//             format!("http://{}", addr),
//             &[(
//                 HeaderName::from_static(TEST_HEADER),
//                 HeaderValue::from_static(hdr),
//             )],
//         )
//         .await;

//     let info = h2
//         .dynamic_table_info(client.local_addr, client.remote_addr)
//         .expect("dynamic_table_info");

//     let expected_size = huffman_encode(hdr).len() * 6;
//     assert_eq!(info.max_size, 128);
//     assert_eq!(info.count, 1);
//     assert_eq!(info.size, expected_size as u16);

//     drop(prog);
//     drop(h2);
//     drop(h1);
// }
