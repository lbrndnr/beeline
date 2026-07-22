# beeline: HTTP parsing in eBPF

<!--[![Crates.io][crates-badge]][crates-url]-->
[![GPL-v3 licensed][gpl-badge]][gpl-url]
[![Build Status][actions-badge]][actions-url]

<!--[crates-badge]: https://img.shields.io/crates/v/bpf-tracing.svg
[crates-url]: https://crates.io/crates/bpf-tracing-->
[gpl-badge]: https://img.shields.io/badge/License-GPL_v3-blue.svg
[gpl-url]: LICENSE
[actions-badge]: https://github.com/lbrndnr/beeline-rs/actions/workflows/ci.yml/badge.svg
[actions-url]: https://github.com/lbrndnr/beeline-rs/actions/workflows/ci.yml

## Build

Install the following packets:

```
sudo apt install autoconf autopoint clang-18 cmake dwarves libcap-dev libdwarf-dev libdw-dev libelf-dev libssl-dev llvm pkg-config
```

Note: depending on your kernel version, you'll have to install [dwarves](https://github.com/acmel/dwarves) from source.

Next, install [libbpf](https://github.com/libbpf/libbpf) and [bpftool](https://github.com/libbpf/bpftool) from source.

Then, generate a new vmlinux file as follows:
```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h
```

You should now be able to compile and test Beeline as follows:

```
RUST_LOG=debug cargo test
```
