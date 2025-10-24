use beeline::h1::Parser;
use reqwest::{Client, header::USER_AGENT};
use utils::{
    server,
    test::{OpenObject, TestProgram},
};

const ECHO_ADDR: &str = "127.0.0.1:12345";

fn assert_match_eq(prog: &TestProgram, idx: usize, expected: &str) {
    let actual = prog.get_match(idx).unwrap().unwrap();
    let actual = String::from_utf8(actual).unwrap();

    assert_eq!(actual.as_str(), expected);
}

fn build_client() -> Client {
    Client::builder().build().expect("client")
}

#[tokio::test]
async fn h1_match_h2_preface() {
    _ = env_logger::try_init();

    let server = server::launch(ECHO_ADDR).await;

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
async fn h1_parse_header_ok() {
    _ = env_logger::try_init();

    let server = server::launch(ECHO_ADDR).await;

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(ECHO_ADDR, &mut open_obj).expect("attach");

    let mut parser = Parser::new();
    parser
        .match_http_hdr("user-agent")
        .expect("match user-agent");
    let parser = parser.attach(prog.prog_fd()).expect("attach parser");

    let client = build_client();
    let user_agent = "beeline";
    let resp = client
        .get(format!("http://{}", ECHO_ADDR))
        .header(USER_AGENT, user_agent)
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
async fn h1_parse_header_malformed() {
    // request with "UsEr-aGgEnT: beeline"

    // request with "user-agent   : beeline"

    // request with "user-agent:beeline"
}

#[tokio::test]
async fn h1_parse_multiple_headers() {}
