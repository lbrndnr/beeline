use std::time::Duration;

use beeline::{h1, h2};
use httlib_huffman as huffman;
use reqwest::{
    Client,
    header::{self, HeaderValue},
};
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

fn build_client() -> Client {
    Client::builder()
        .http2_prior_knowledge()
        .http2_max_header_list_size(1024)
        .timeout(Duration::from_secs(1))
        .build()
        .expect("client")
}

#[tokio::test]
async fn parse_indexed_header_field() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj).expect("attach");

    let h1 = h1::Parser::new()
        .match_preface()
        .expect("match preface")
        .replace_parse_msg("parse_h1")
        .replace_matched("matched_h1")
        .replace_extract("extract_h1_match")
        .attach(prog.prog_fd())
        .expect("attach parser");

    let h2 = h2::Parser::new()
        .capture_http_hdr("method")
        .expect("match method")
        .replace_parse_msg("parse_h2")
        .replace_extract("extract_h2_match")
        .attach(prog.prog_fd())
        .expect("attach parser");

    let client = build_client();
    let resp = client
        .get(format!("http://{}", addr))
        .send()
        .await
        .expect("request");

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

    let h1 = h1::Parser::new()
        .match_preface()
        .expect("match preface")
        .replace_parse_msg("parse_h1")
        .replace_matched("matched_h1")
        .replace_extract("extract_h1_match")
        .attach(prog.prog_fd())
        .expect("attach parser");

    let h2 = h2::Parser::new()
        .capture_http_hdr("authorization")
        .expect("match authorization")
        .replace_parse_msg("parse_h2")
        .replace_extract("extract_h2_match")
        .attach(prog.prog_fd())
        .expect("attach parser");

    let client = build_client();
    let resp = client
        .get(format!("http://{}", addr))
        .basic_auth("beeline", Some("beeline"))
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    assert_match_eq(&prog, 0, Some("Basic YmVlbGluZTpiZWVsaW5l")); // beeline:beeline in base64

    drop(prog);
    drop(h2);
    drop(h1);
}

#[tokio::test]
async fn parse_literal_header_field_no_indexing_not_indexed() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj).expect("attach program");

    let h1 = h1::Parser::new()
        .match_preface()
        .expect("match preface")
        .replace_parse_msg("parse_h1")
        .replace_matched("matched_h1")
        .replace_extract("extract_h1_match")
        .attach(prog.prog_fd())
        .expect("attach parser");

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

    let client = build_client();
    let resp = client
        .get(format!("http://{}", addr))
        .header("sensitive", val)
        .send()
        .await
        .expect("request");

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

    let h1 = h1::Parser::new()
        .match_preface()
        .expect("match preface")
        .replace_parse_msg("parse_h1")
        .replace_matched("matched_h1")
        .replace_extract("extract_h1_match")
        .attach(prog.prog_fd())
        .expect("attach parser");

    let h2 = h2::Parser::new()
        .capture_http_hdr("user-agent")
        .expect("match user-agent")
        .capture_http_hdr("path")
        .expect("match path")
        .replace_parse_msg("parse_h2")
        .replace_extract("extract_h2_match")
        .attach(prog.prog_fd())
        .expect("attach parser");

    let client = build_client();
    let user_agent = "beeline";
    let path = "/bee/1234";
    let resp = client
        .get(format!("http://{}{}", addr, path))
        .header(header::USER_AGENT, user_agent)
        .send()
        .await
        .expect("request");

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

    let h1 = h1::Parser::new()
        .match_preface()
        .expect("match preface")
        .replace_parse_msg("parse_h1")
        .replace_matched("matched_h1")
        .replace_extract("extract_h1_match")
        .attach(prog.prog_fd())
        .expect("attach parser");

    let h2 = h2::Parser::new()
        .capture_http_hdr("user-agent")
        .expect("match user-agent")
        .capture_http_hdr("accept-language")
        .expect("match accept-language")
        .replace_parse_msg("parse_h2")
        .replace_extract("extract_h2_match")
        .attach(prog.prog_fd())
        .expect("attach parser");

    let client = build_client();
    let user_agent = "beeline";
    let lang = "sumsum";
    let resp = client
        .get(format!("http://{}", addr))
        .header(header::USER_AGENT, user_agent)
        .header(header::ACCEPT_LANGUAGE, lang)
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    assert_match_eq(&prog, 0, Some(user_agent));
    assert_match_eq(&prog, 1, Some(lang));

    // repeat the request with other headers
    // this will check if it indexes the dynamic table correctly
    let resp = client
        .get(format!("http://{}", addr))
        .header(header::VIA, "the hive")
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    assert_match_eq(&prog, 0, None);
    assert_match_eq(&prog, 1, None);

    // we repeat this request to check if the header has been added to the dynamic table
    let resp = client
        .get(format!("http://{}", addr))
        .header(header::ACCEPT_LANGUAGE, lang)
        .header(header::USER_AGENT, user_agent)
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    assert_match_eq(&prog, 0, Some(user_agent));
    assert_match_eq(&prog, 1, Some(lang));

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

//     let client = build_client();
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
