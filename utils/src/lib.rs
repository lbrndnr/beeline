#[allow(dead_code)]
mod huffman;
pub mod test;

// const STATIC_TABLE: Vec<(String, Option<String>)> = vec![
//     (":authority".to_string(), None),
//     (":method".to_string(), Some("GET".to_string())),
//     (":method".to_string(), Some("POST".to_string())),
//     (":path".to_string(), Some("/".to_string())),
//     (":path".to_string(), Some("/index.html".to_string())),
//     (":scheme".to_string(), Some("http".to_string())),
//     (":scheme".to_string(), Some("https".to_string())),
//     (":status".to_string(), Some("200".to_string())),
//     (":status".to_string(), Some("204".to_string())),
//     (":status".to_string(), Some("206".to_string())),
//     (":status".to_string(), Some("304".to_string())),
//     (":status".to_string(), Some("400".to_string())),
//     (":status".to_string(), Some("404".to_string())),
//     (":status".to_string(), Some("500".to_string())),
//     ("accept-charset".to_string(), None),
//     (
//         "accept-encoding".to_string(),
//         Some("gzip, deflate".to_string()),
//     ),
//     ("accept-language".to_string(), None),
//     ("accept-ranges".to_string(), None),
//     ("accept".to_string(), None),
//     ("access-control-allow-origin".to_string(), None),
//     ("age".to_string(), None),
//     ("allow".to_string(), None),
//     ("authorization".to_string(), None),
//     ("cache-control".to_string(), None),
//     ("content-disposition".to_string(), None),
//     ("content-encoding".to_string(), None),
//     ("content-language".to_string(), None),
//     ("content-length".to_string(), None),
//     ("content-location".to_string(), None),
//     ("content-range".to_string(), None),
//     ("content-type".to_string(), None),
//     ("cookie".to_string(), None),
//     ("date".to_string(), None),
//     ("etag".to_string(), None),
//     ("expect".to_string(), None),
//     ("expires".to_string(), None),
//     ("from".to_string(), None),
//     ("host".to_string(), None),
//     ("if-match".to_string(), None),
//     ("if-modified-since".to_string(), None),
//     ("if-none-match".to_string(), None),
//     ("if-range".to_string(), None),
//     ("if-unmodified-since".to_string(), None),
//     ("last-modified".to_string(), None),
//     ("link".to_string(), None),
//     ("location".to_string(), None),
//     ("max-forwards".to_string(), None),
//     ("proxy-authenticate".to_string(), None),
//     ("proxy-authorization".to_string(), None),
//     ("range".to_string(), None),
//     ("referer".to_string(), None),
//     ("refresh".to_string(), None),
//     ("retry-after".to_string(), None),
//     ("server".to_string(), None),
//     ("set-cookie".to_string(), None),
//     ("strict-transport-security".to_string(), None),
//     ("transfer-encoding".to_string(), None),
//     ("user-agent".to_string(), None),
//     ("vary".to_string(), None),
//     ("via".to_string(), None),
//     ("www-authenticate".to_string(), None),
// ];

// fn main() {
//     let mut dst = BytesMut::with_capacity(128);
//     let val = "method";
//     huffman::encode(val.as_bytes(), &mut dst);
//     println!("{:?}", dst);

//     let mut dst = BytesMut::with_capacity(128);
//     let val = "GET";
//     huffman::encode(val.as_bytes(), &mut dst);
//     println!("{:?}", dst);
// }
