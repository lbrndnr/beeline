use beeline::{h1, h2};
use httlib_huffman as huffman;
use reqwest::{Client, header};
use utils::{
    server,
    test::{OpenObject, TestProgram},
};

const ECHO_ADDR: &str = "127.0.0.1:12345";

fn assert_match_eq(prog: &TestProgram, idx: usize, expected: &str) {
    let actual_hf = prog.get_match(idx).unwrap().unwrap();
    let mut actual = Vec::new();
    huffman::decode(&actual_hf, &mut actual, huffman::DecoderSpeed::OneBit).unwrap();
    let actual = String::from_utf8(actual).unwrap();

    assert_eq!(actual.as_str(), expected);
}

fn build_client() -> Client {
    Client::builder()
        .http2_prior_knowledge()
        .build()
        .expect("client")
}

#[tokio::test]
async fn parse_indexed_header_field() {
    _ = env_logger::try_init();

    let server = server::launch(ECHO_ADDR).await;

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(ECHO_ADDR, &mut open_obj).expect("attach");

    let h1 = h1::Parser::new()
        .match_preface()
        .expect("match preface")
        .replace_parse("parse_h1")
        .replace_matched("matched_h1")
        .replace_extract("extract_h1_match")
        .attach(prog.prog_fd())
        .expect("attach parser");

    let h2 = h2::Parser::new()
        .capture_http_hdr("method")
        .expect("match method")
        .replace_parse("parse_h2")
        .replace_extract("extract_h2_match")
        .attach(prog.prog_fd())
        .expect("attach parser");

    let client = build_client();
    let resp = client
        .get(format!("http://{}", ECHO_ADDR))
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    assert_match_eq(&prog, 0, "GET");

    drop(server);
    drop(prog);
    drop(h2);
    drop(h1);
}

#[tokio::test]
async fn parse_literal_header_field_no_indexing_indexed() {
    _ = env_logger::try_init();

    let server = server::launch(ECHO_ADDR).await;

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(ECHO_ADDR, &mut open_obj).expect("attach program");

    let h1 = h1::Parser::new()
        .match_preface()
        .expect("match preface")
        .replace_parse("parse_h1")
        .replace_matched("matched_h1")
        .replace_extract("extract_h1_match")
        .attach(prog.prog_fd())
        .expect("attach parser");

    let h2 = h2::Parser::new()
        .capture_http_hdr("authorization")
        .expect("match authorization")
        .replace_parse("parse_h2")
        .replace_extract("extract_h2_match")
        .attach(prog.prog_fd())
        .expect("attach parser");

    let client = build_client();
    let resp = client
        .get(format!("http://{}", ECHO_ADDR))
        .basic_auth("beeline", Some("beeline"))
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    assert_match_eq(&prog, 0, "Basic YmVlbGluZTpiZWVsaW5l"); // beeline:beeline in base64

    drop(server);
    drop(prog);
    drop(h2);
    drop(h1);
}

#[tokio::test]
async fn parse_literal_header_field_incremental_indexing_indexed() {
    _ = env_logger::try_init();

    let server = server::launch(ECHO_ADDR).await;

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(ECHO_ADDR, &mut open_obj).expect("attach program");

    let h1 = h1::Parser::new()
        .match_preface()
        .expect("match preface")
        .replace_parse("parse_h1")
        .replace_matched("matched_h1")
        .replace_extract("extract_h1_match")
        .attach(prog.prog_fd())
        .expect("attach parser");

    let h2 = h2::Parser::new()
        .capture_http_hdr("user-agent")
        .expect("match user-agent")
        .replace_parse("parse_h2")
        .replace_extract("extract_h2_match")
        .attach(prog.prog_fd())
        .expect("attach parser");

    let client = build_client();
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
    drop(h2);
    drop(h1);
}

#[tokio::test]
async fn parse_literal_header_field_incremental_indexing_in_dynamic_table() {
    _ = env_logger::try_init();

    let server = server::launch(ECHO_ADDR).await;

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(ECHO_ADDR, &mut open_obj).expect("attach program");

    let h1 = h1::Parser::new()
        .match_preface()
        .expect("match preface")
        .replace_parse("parse_h1")
        .replace_matched("matched_h1")
        .replace_extract("extract_h1_match")
        .attach(prog.prog_fd())
        .expect("attach parser");

    let h2 = h2::Parser::new()
        .capture_http_hdr("user-agent")
        .expect("match user-agent")
        .capture_http_hdr("accept-language")
        .expect("match accept-language")
        .replace_parse("parse_h2")
        .replace_extract("extract_h2_match")
        .attach(prog.prog_fd())
        .expect("attach parser");

    let client = build_client();
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

    // now we add another header to check if we can still retrieve the headers
    // in the dynamic table
    let resp = client
        .get(format!("http://{}", ECHO_ADDR))
        .header(header::ACCEPT_LANGUAGE, lang)
        .header(header::USER_AGENT, user_agent)
        .header(header::ORIGIN, "the hive")
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    assert_match_eq(&prog, 0, user_agent);
    assert_match_eq(&prog, 1, lang);

    drop(server);
    drop(prog);
    drop(h2);
    drop(h1);
}
