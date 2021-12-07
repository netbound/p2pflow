# p2pflow

> An eBPF application to monitor Ethereum p2p network traffic, built with eBPF.

## Requirements

* [Rust](https://www.rust-lang.org/tools/install)
* Up-to-date Linux kernel. The project is built on technology like `CO-RE` and `BTF`, which is only
available in more recent kernels (5.0-ish). Ubuntu 20.10 has configured and packaged all the required dependencies.
* `vmlinux.h`, which you can generate like this:
```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
```
You can verify whether your kernel was built with BTF enabled:

```bash
cat /boot/config-$(uname -r) | grep CONFIG_DEBUG_INFO_BTF
```
## Install & Build
```
git clone --recurse-submodules -j8 https://github.com/netbound/p2pflow
```

```bash
cargo build --release
```

## Run
```bash
sudo ./target/release/p2pflow --port 30303 --pname geth
```