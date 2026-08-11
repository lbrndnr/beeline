use beeline::h1;
use http::{HeaderName, header};
use reqwest::Client;
use utils::{
    server,
    test::{OpenObject, TestProgram},
};

fn assert_match_eq(prog: &TestProgram, idx: usize, expected: &str) {
    let actual = prog.get_match(idx).unwrap().unwrap();
    let actual = String::from_utf8(actual).unwrap();

    assert_eq!(actual.as_str(), expected);
}

fn build_client() -> Client {
    Client::builder().build().expect("client")
}

fn attach_h1_parser(prog_fd: i32, match_preface: bool, hdrs: &[HeaderName]) -> h1::AttachedParser {
    let mut h1 = h1::Parser::new();
    if match_preface {
        h1 = h1.match_h2_preface().expect("match preface");
    }
    for hdr in hdrs {
        h1 = h1.capture_hdr(hdr).expect("capture {hdr}");
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
    let prog = TestProgram::attach(addr, &mut open_obj).expect("attach");

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
    let prog = TestProgram::attach(addr, &mut open_obj).expect("attach");
    let _h1 = attach_h1_parser(prog.prog_fd(), true, &[header::USER_AGENT]);

    let client = build_client();
    let user_agent = "beeline";
    let resp = client
        .get(format!("http://{}", addr))
        .header(header::USER_AGENT, user_agent)
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    assert_match_eq(&prog, 1, user_agent);
}

// #[tokio::test]
// async fn ignore_header_case() {
//     let server = server::launch().await;

//     let mut open_obj = OpenObject::new();
//     let prog = TestProgram::attach(addr, &mut open_obj).expect("attach");

//     let _h1 = Parser::new()
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
//         .get(format!("http://{}", addr))
//         .header("UsEr-aGEnT", user_agent) // TODO: this doesn't seem to be working
//         .send()
//         .await
//         .expect("request");

//     assert_eq!(resp.status(), 200);
//     assert_match_eq(&prog, 1, user_agent);

// }

// #[tokio::test]
// async fn ignores_header_whitespace() {
//     let server = server::launch().await;

//     let mut open_obj = OpenObject::new();
//     let prog = TestProgram::attach(addr, &mut open_obj).expect("attach");

//     let _h1 = Parser::new()
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
//         .get(format!("http://{}", addr))
//         .header("user-agent   ", format!("  {}", user_agent))
//         .send()
//         .await
//         .expect("request");

//     assert_eq!(resp.status(), 200);
//     assert_match_eq(&prog, 1, user_agent);

// }

#[tokio::test]
async fn parse_subsequent_headers() {
    let addr = server::launch().await.expect("launch server");

    let mut open_obj = OpenObject::new();
    let prog = TestProgram::attach(addr, &mut open_obj).expect("attach");

    let _h1 = attach_h1_parser(
        prog.prog_fd(),
        true,
        &[header::USER_AGENT, header::ACCEPT_LANGUAGE],
    );

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
    assert_match_eq(&prog, 1, user_agent);
    assert_match_eq(&prog, 2, lang);
}
