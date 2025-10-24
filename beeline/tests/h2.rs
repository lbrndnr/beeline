use beeline::h2::Parser;
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
async fn h2_parse_indexed_header_field() {
    _ = env_logger::try_init();

    let server = server::launch(ECHO_ADDR).await;

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(ECHO_ADDR, &mut open_obj).expect("attach");

    let mut parser = Parser::new();
    parser.capture_http_hdr("method").expect("match method");
    let parser = parser.attach(prog.prog_fd()).expect("attach parser");

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
    drop(parser);
}

#[tokio::test]
async fn h2_parse_literal_header_field_no_indexing_indexed() {
    _ = env_logger::try_init();

    let server = server::launch(ECHO_ADDR).await;

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(ECHO_ADDR, &mut open_obj).expect("attach program");

    let mut parser = Parser::new();
    parser
        .capture_http_hdr("authorization")
        .expect("match authorization");
    let parser = parser.attach(prog.prog_fd()).expect("attach parser");

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
    drop(parser);
}

#[tokio::test]
async fn h2_parse_literal_header_field_incremental_indexing_indexed() {
    _ = env_logger::try_init();

    let server = server::launch(ECHO_ADDR).await;

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(ECHO_ADDR, &mut open_obj).expect("attach program");

    let mut parser = Parser::new();
    parser
        .capture_http_hdr("user-agent")
        .expect("match user-agent");
    let parser = parser.attach(prog.prog_fd()).expect("attach parser");

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
    drop(parser);
}

#[tokio::test]
async fn h2_parse_literal_header_field_incremental_indexing_in_dynamic_table() {
    _ = env_logger::try_init();

    let server = server::launch(ECHO_ADDR).await;

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

    drop(server);
    drop(prog);
    drop(parser);
}
