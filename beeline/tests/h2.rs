use std::net::SocketAddr;

use ::h2::{RecvStream, client};
use beeline::{h1, h2};
use bytes::Bytes;
use httlib_huffman as huffman;
use http::{HeaderName, HeaderValue, Request, Response, header};
use tokio::net::TcpStream;
use utils::{
    server,
    test::{Direction, TestProgram},
};
use xbpf::OpenObject;

const TEST_HEADER: HeaderName = HeaderName::from_static("testheader");
const METHOD_HEADER: HeaderName = HeaderName::from_static("method");
const AUTHORITY_HEADER: HeaderName = HeaderName::from_static("authority");
const PATH_HEADER: HeaderName = HeaderName::from_static("path");

fn huffman_decode(val: &[u8]) -> String {
    let mut res = Vec::new();
    huffman::decode(val, &mut res, huffman::DecoderSpeed::OneBit).unwrap();
    String::from_utf8(res).unwrap()
}

fn dynamic_table_size_for_headers(headers: &[(HeaderName, HeaderValue)]) -> u32 {
    headers.iter().fold(0, |acc, (k, v)| {
        acc + (k.as_str().len() + v.len() + 32) as u32
    })
}

fn assert_match_eq(prog: &TestProgram, idx: usize, expected: Option<&HeaderValue>) {
    let actual_hf = prog.get_match(idx).expect("get_match");
    let actual = actual_hf.map(|val| huffman_decode(&val));

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

fn attach_preface_parser(prog_fd: i32) -> h1::AttachedParser {
    h1::Parser::new()
        .match_h2_preface()
        .replace_parse_msg("parse_h1")
        .replace_matched("matched_h1")
        .replace_extract("extract_h1_match")
        .attach(prog_fd)
        .expect("attach parser")
}

fn attach_h2_parser(prog_fd: i32, hdrs: &[HeaderName]) -> h2::AttachedParser {
    let mut h2 = h2::Parser::new();
    for hdr in hdrs {
        h2 = h2.capture_hdr(hdr).expect(&format!("capture {:?}", hdr));
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
    let prog = TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let _h2 = attach_h2_parser(prog.prog_fd(), &[METHOD_HEADER]);

    let client = Client::connect(addr, None).await;
    client.get(format!("http://{}", addr), &[]).await;

    let method_val = HeaderValue::from_static("GET");
    assert_match_eq(&prog, 0, Some(&method_val));
}

#[tokio::test]
async fn parse_header_field_no_indexing_name_indexed_in_static_table() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach program");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let _h2 = attach_h2_parser(prog.prog_fd(), &[header::AUTHORIZATION]);

    let auth_val = HeaderValue::from_static("Basic YmVlbGluZTpiZWVsaW5l"); // beeline:beeline in base64

    let client = Client::connect(addr, None).await;
    client
        .get(
            format!("http://{}", addr),
            &[(header::AUTHORIZATION, auth_val.clone())],
        )
        .await;

    assert_match_eq(&prog, 0, Some(&auth_val));
}

#[tokio::test]
async fn parse_header_field_never_indexing_name_indexed_in_static_table() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach program");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let _h2 = attach_h2_parser(prog.prog_fd(), &[TEST_HEADER]);

    let mut test_header_val = HeaderValue::from_static("my secret");
    test_header_val.set_sensitive(true);

    let client = Client::connect(addr, None).await;
    client
        .get(
            format!("http://{}", addr),
            &[(TEST_HEADER, test_header_val.clone())],
        )
        .await;

    assert_match_eq(&prog, 0, Some(&test_header_val));
}

#[tokio::test]
async fn parse_header_field_never_indexing_new_name() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach program");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let _h2 = attach_h2_parser(prog.prog_fd(), &[TEST_HEADER]);

    let mut test_header_val = HeaderValue::from_static("my secret");
    test_header_val.set_sensitive(true);

    let client = Client::connect(addr, None).await;
    client
        .get(
            format!("http://{}", addr),
            &[(TEST_HEADER, test_header_val.clone())],
        )
        .await;

    assert_match_eq(&prog, 0, Some(&test_header_val));
}

#[tokio::test]
async fn parse_header_field_incremental_indexing_name_indexed_in_static_table() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach program");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let _h2 = attach_h2_parser(prog.prog_fd(), &[header::USER_AGENT, PATH_HEADER]);

    let user_agent_val = HeaderValue::from_static("beeline");
    let path = "/bee/1234";
    let path_val = HeaderValue::from_static(path);

    let client = Client::connect(addr, None).await;
    client
        .get(
            format!("http://{}{}", addr, path),
            &[(header::USER_AGENT, user_agent_val.clone())],
        )
        .await;
    assert_match_eq(&prog, 0, Some(&user_agent_val));
    assert_match_eq(&prog, 1, Some(&path_val));
}

// #[tokio::test]
// async fn parse_header_field_incremental_indexing_name_indexed_in_dynamic_table() {
//     todo!();
// }

#[tokio::test]
async fn parse_header_field_incremental_indexing_new_name() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach program");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let _h2 = attach_h2_parser(prog.prog_fd(), &[TEST_HEADER, PATH_HEADER]);

    let test_header_val = HeaderValue::from_static("beeline");
    let path = "/bee/1234";
    let path_val = HeaderValue::from_static(&path);

    let client = Client::connect(addr, None).await;
    client
        .get(
            format!("http://{}{}", addr, path),
            &[(TEST_HEADER, test_header_val.clone())],
        )
        .await;
    assert_match_eq(&prog, 0, Some(&test_header_val));
    assert_match_eq(&prog, 1, Some(&path_val));
}

#[tokio::test]
async fn parse_header_field_incremental_indexing_indexed_in_dynamic_table() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach program");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let _h2 = attach_h2_parser(
        prog.prog_fd(),
        &[header::USER_AGENT, header::ACCEPT_LANGUAGE],
    );

    let user_agent_val = HeaderValue::from_static("beeline");
    let lang_val = HeaderValue::from_static("sumsum");

    let client = Client::connect(addr, None).await;
    client
        .get(
            format!("http://{}", addr),
            &[
                (header::USER_AGENT, user_agent_val.clone()),
                (header::ACCEPT_LANGUAGE, lang_val.clone()),
            ],
        )
        .await;
    assert_match_eq(&prog, 0, Some(&user_agent_val));
    assert_match_eq(&prog, 1, Some(&lang_val));

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
                (header::ACCEPT_LANGUAGE, lang_val.clone()),
                (header::USER_AGENT, user_agent_val.clone()),
            ],
        )
        .await;
    assert_match_eq(&prog, 0, Some(&user_agent_val));
    assert_match_eq(&prog, 1, Some(&lang_val));
}

#[tokio::test]
async fn update_dynamic_table_size() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach program");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let h2 = attach_h2_parser(prog.prog_fd(), &[]);

    let client = Client::connect(addr, Some(1234)).await;
    client.get(format!("http://{}", addr), &[]).await;

    let max_size = h2
        .dynamic_table_info(client.local_addr, client.remote_addr)
        .expect("dynamic_table_info")
        .max_size;
    assert_eq!(max_size, 1234);
}

#[tokio::test]
async fn evict_header_field_from_dynamic_table() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog =
        TestProgram::attach(addr, &mut open_obj, Direction::Downstream).expect("attach program");

    let _h1 = attach_preface_parser(prog.prog_fd());
    let h2 = attach_h2_parser(prog.prog_fd(), &[TEST_HEADER, header::USER_AGENT]);

    let test_header_val = HeaderValue::from_static("asdfqwerasdfqwerasdfqwerasdfqwer");
    let user_agent_val = HeaderValue::from_static("test-agent");

    // this request immediately exceeds the dynamic table limit
    let client = Client::connect(addr, Some(254)).await;
    client
        .get(
            format!("http://{}", addr),
            &[(TEST_HEADER, test_header_val.clone())],
        )
        .await;

    let info = h2
        .dynamic_table_info(client.local_addr, client.remote_addr)
        .expect("dynamic_table_info");

    let authority = addr.to_string();
    let expected_dt = &[
        (TEST_HEADER, test_header_val.clone()),
        (
            AUTHORITY_HEADER,
            HeaderValue::from_str(&authority.as_str()).unwrap(),
        ),
    ];
    assert_eq!(info.max_size, 254);
    assert_eq!(info.count, expected_dt.len() as u32);
    assert_eq!(info.size, dynamic_table_size_for_headers(expected_dt));
    assert_match_eq(&prog, 0, Some(&test_header_val));

    client
        .get(
            format!("http://{}", addr),
            &[(header::USER_AGENT, user_agent_val.clone())],
        )
        .await;

    // this should add the user-agent to the dynamic table, but not evict TEST_HEADER
    let info = h2
        .dynamic_table_info(client.local_addr, client.remote_addr)
        .expect("dynamic_table_info");
    let expected_dt = &[
        (TEST_HEADER, test_header_val.clone()),
        (
            AUTHORITY_HEADER,
            HeaderValue::from_str(&authority.as_str()).unwrap(),
        ),
        (header::USER_AGENT, user_agent_val.clone()),
    ];
    assert_eq!(info.max_size, 254);
    assert_eq!(info.count, expected_dt.len() as u32);
    assert_eq!(info.size, dynamic_table_size_for_headers(expected_dt));
    assert_match_eq(&prog, 1, Some(&user_agent_val));

    client
        .get(
            format!("http://{}", addr),
            &[(header::USER_AGENT, test_header_val.clone())],
        )
        .await;

    // this should evict all entries, and add back the user-agent
    let info = h2
        .dynamic_table_info(client.local_addr, client.remote_addr)
        .expect("dynamic_table_info");
    let expected_dt = &[(header::USER_AGENT, test_header_val.clone())];
    assert_eq!(info.max_size, 254);
    assert_eq!(info.count, expected_dt.len() as u32);
    assert_eq!(info.size, dynamic_table_size_for_headers(expected_dt));
    assert_match_eq(&prog, 1, Some(&test_header_val));
}
