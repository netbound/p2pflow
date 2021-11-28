# p2pflow

> An eBPF application to monitor Ethereum p2p network traffic.

## Requirements

### Kernel

The project is built on technology like `CO-RE` and `BTF`, which is only
available in more recent kernels (5.0-ish). Ubuntu 20.10 has configured and
packaged all the required dependencies.

### Generate `vmlinux.h`

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
```

You can verify whether your kernel was built with BTF enabled:

```bash
cat /boot/config-$(uname -r) | grep CONFIG_DEBUG_INFO_BTF
```

## Build
### Cargo

```bash
cargo build --release
```

## Run

Start the program to instrument the eBPF probe and listen to events:

```bash
cargo run --release
```