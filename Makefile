APP = p2pflow

install:
	cargo install --path .
	sudo setcap cap_sys_admin+eip $(HOME)/.cargo/bin/$(APP)