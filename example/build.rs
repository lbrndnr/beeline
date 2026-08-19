use beeline::build::clang_args;
use xbpf::build::Builder;

fn main() {
    Builder::new()
        .clang_arg(clang_args().iter())
        .export_headers()
        .build();
}
