# Beeline

Beeline is an HTTP parser in eBPF.

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
