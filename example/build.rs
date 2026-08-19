use std::ffi::OsString;
use xbpf::build::Builder;

fn main() {
    let mut args = vec![OsString::from("-I"), OsString::from("../include")];
    args.extend_from_slice(&beeline_include::clang_args().unwrap());

    Builder::new()
        .clang_arg(args.iter())
        .export_headers()
        .build();
}
