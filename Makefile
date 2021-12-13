APP = p2pflow

.PHONY: install
install:
	cargo install --path .
	sudo setcap cap_sys_admin,cap_sys_resource+eip $(HOME)/.cargo/bin/$(APP)

.PHONY: vmlinux
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h