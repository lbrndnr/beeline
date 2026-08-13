# Beeline: Application-Layer Parsing in eBPF

<!--[![Crates.io][crates-badge]][crates-url]-->
[![GPL-v3 licensed][gpl-badge]][gpl-url]
[![Build Status][actions-badge]][actions-url]

<!--[crates-badge]: https://img.shields.io/crates/v/bpf-tracing.svg
[crates-url]: https://crates.io/crates/bpf-tracing-->
[gpl-badge]: https://img.shields.io/badge/License-GPL_v3-blue.svg
[gpl-url]: LICENSE
[actions-badge]: https://github.com/lbrndnr/beeline-rs/actions/workflows/ci.yml/badge.svg
[actions-url]: https://github.com/lbrndnr/beeline-rs/actions/workflows/ci.yml

Beeline is an application-layer parser for eBPF. This allows you to process protocols (see below for a table of supported protocols) directly in the kernel, which can be much more efficient than user space processing. With Beeline, you can for example monitor application-layer traffic, redirect it based on its payload, or respond to it, directly from the kernel.

Protocol      | Status
------------- | -------------
HTTP/1.1      | ✅ 
HTTP/2        | ✅
gRPC          | WIP

## Build

To build and test Beeline, you need to install the following packages:

```bash
sudo apt install clang-18 llvm-18 libelf-dev zlib1g-dev linux-headers-`uname -r` libbpf-dev
```

Then, generate a new `vmlinux.h` file by first installing [bpftool](https://github.com/libbpf/bpftool) from source and then run:
```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h
```

You should now be able to compile and test Beeline as follows:

```bash
RUST_LOG=trace cargo test
```

## Running the Example

Once you can build Beeline, you can also run the example. It is a simple HTTP server, with Beeline attached to it. It will serve some static files directly from the kernel. To run it, first start the server:
```bash
cargo run --bin example
```

Then, in another terminal, make a request to the server:
```bash
curl -vv http://127.0.0.1:8080/index.html
```
