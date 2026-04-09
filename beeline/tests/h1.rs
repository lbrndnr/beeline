use beeline::h1::Parser;
use reqwest::{Client, header};
use utils::{
    server,
    test::{OpenObject, TestProgram, setup_tracing},
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
async fn match_h2_preface() {
    setup_tracing();
    let server = server::launch(ECHO_ADDR).await;

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(ECHO_ADDR, &mut open_obj).expect("attach");

    let h1 = Parser::new()
        .match_preface()
        .expect("match preface")
        .replace_parse_msg("parse_h1")
        .replace_matched("matched_h1")
        .replace_extract("extract_h1_match")
        .attach(prog.prog_fd())
        .expect("attach parser");

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
    drop(h1);
}

#[tokio::test]
async fn parse_simple_header() {
    setup_tracing();

    let server = server::launch(ECHO_ADDR).await;

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(ECHO_ADDR, &mut open_obj).expect("attach");

    let h1 = Parser::new()
        .match_preface()
        .expect("match preface")
        .match_http_hdr("user-agent")
        .expect("match user-agent")
        .replace_parse_msg("parse_h1")
        .replace_matched("matched_h1")
        .replace_extract("extract_h1_match")
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
    assert_match_eq(&prog, 1, user_agent);

    drop(server);
    drop(prog);
    drop(h1);
}

// #[tokio::test]
// async fn ignore_header_case() {
//     setup_tracing();

//     let server = server::launch(ECHO_ADDR).await;

//     let mut open_obj = OpenObject::new();
//     let prog = TestProgram::attach(ECHO_ADDR, &mut open_obj).expect("attach");

//     let h1 = Parser::new()
//         .match_preface()
//         .expect("match preface")
//         .match_http_hdr("user-agent")
//         .expect("match user-agent")
//         .replace_parse_msg("parse_h1")
//         .replace_matched("matched_h1")
//         .replace_extract("extract_h1_match")
//         .attach(prog.prog_fd())
//         .expect("attach parser");

//     let client = build_client();
//     let user_agent = "beeline";
//     let resp = client
//         .get(format!("http://{}", ECHO_ADDR))
//         .header("UsEr-aGEnT", user_agent) // TODO: this doesn't seem to be working
//         .send()
//         .await
//         .expect("request");

//     assert_eq!(resp.status(), 200);
//     assert_match_eq(&prog, 1, user_agent);

//     drop(server);
//     drop(prog);
//     drop(h1);
// }

// #[tokio::test]
// async fn ignores_header_whitespace() {
//     setup_tracing();

//     let server = server::launch(ECHO_ADDR).await;

//     let mut open_obj = OpenObject::new();
//     let prog = TestProgram::attach(ECHO_ADDR, &mut open_obj).expect("attach");

//     let h1 = Parser::new()
//         .match_preface()
//         .expect("match preface")
//         .match_http_hdr("user-agent")
//         .expect("match user-agent")
//         .replace_parse_msg("parse_h1")
//         .replace_matched("matched_h1")
//         .replace_extract("extract_h1_match")
//         .attach(prog.prog_fd())
//         .expect("attach parser");

//     let client = build_client();
//     let user_agent = "beeline";
//     let resp = client
//         .get(format!("http://{}", ECHO_ADDR))
//         .header("user-agent   ", format!("  {}", user_agent))
//         .send()
//         .await
//         .expect("request");

//     assert_eq!(resp.status(), 200);
//     assert_match_eq(&prog, 1, user_agent);

//     drop(server);
//     drop(prog);
//     drop(h1);
// }

#[tokio::test]
async fn parse_subsequent_headers() {
    setup_tracing();

    let server = server::launch(ECHO_ADDR).await;

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(ECHO_ADDR, &mut open_obj).expect("attach");

    let h1 = Parser::new()
        .match_preface()
        .expect("match preface")
        .match_http_hdr("user-agent")
        .expect("match user-agent")
        .match_http_hdr("accept-language")
        .expect("match accept-language")
        .replace_parse_msg("parse_h1")
        .replace_matched("matched_h1")
        .replace_extract("extract_h1_match")
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
    assert_match_eq(&prog, 1, user_agent);
    assert_match_eq(&prog, 2, lang);

    drop(server);
    drop(prog);
    drop(h1);
}
