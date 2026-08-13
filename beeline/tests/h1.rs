use beeline::h1;
use http::{HeaderName, HeaderValue, header};
use reqwest::Client;
use utils::{
    server,
    test::{OpenObject, TestProgram},
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

fn attach_h1_parser(prog_fd: i32, match_preface: bool, hdrs: &[HeaderName]) -> h1::AttachedParser {
    let mut h1 = h1::Parser::new();
    if match_preface {
        h1 = h1.match_h2_preface().expect("match preface");
    }
    for hdr in hdrs {
        h1 = h1.capture_hdr(hdr).expect(&format!("capture {:?}", hdr));
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
    let prog = TestProgram::attach(addr, &mut open_obj).expect("attach");

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
    let prog = TestProgram::attach(addr, &mut open_obj).expect("attach");

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
