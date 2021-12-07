#include "vmlinux.h"
#include "p2pflow.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define HOSTNAME_LEN 84
#define ETH_HLEN 14

#define ETH_P_IP 0x0800
#define MAX_PEERS 4096

#define AF_INET 2	/* IP protocol family.  */
#define AF_INET6 10 /* IP version 6.  */

#define ETH_P2P_PORT 30303

// rodata section, changed in userspace before loading BPF program
const volatile u16 p2p_port = ETH_P2P_PORT;
const volatile char process_name[16] = "geth";

// dummy instances to generate skeleton types
struct peer_v4_t _ipv4 = {};
struct peer_v6_t _ipv6 = {};
struct value_t _val = {};

struct bpf_map_def SEC("maps") trackers_v4 = {
	.type = BPF_MAP_TYPE_HASH,
	.max_entries = MAX_PEERS,
	.key_size = sizeof(struct peer_v4_t),
	.value_size = sizeof(struct value_t) // bytes sent/recvd
};

struct bpf_map_def SEC("maps") trackers_v6 = {
	.type = BPF_MAP_TYPE_HASH,
	.max_entries = MAX_PEERS,
	.key_size = sizeof(struct peer_v6_t),
	.value_size = sizeof(struct value_t) // bytes sent/recvd
};

// Maps all sockets to their corresponding peers
struct bpf_map_def SEC("maps") sockets = {
	.type = BPF_MAP_TYPE_HASH,
	.max_entries = MAX_PEERS,
	.key_size = sizeof(kuid_t),
	.value_size = sizeof(struct peer_t)};

static __always_inline u32 get_pid()
{
	u64 tgid = bpf_get_current_pid_tgid();
	pid_t pid = tgid >> 32;
	return (u32)pid;
}

static __always_inline char *get_pname()
{
	char name[16];
	bpf_get_current_comm(name, 16);
	return name;
}

// Checks if the process name is the one we want.
static __always_inline bool is_eth_pname(char *str)
{
	char comparand[sizeof(process_name)];
	bpf_probe_read(&comparand, sizeof(comparand), str);
	for (int i = 0; i < 4; ++i)
		if (process_name[i] != comparand[i])
			return false;
	return true;
}

// Returns 1 if new entry was created, 0 for update
//
// dir (direction): out = true, in = false
static __always_inline int handle_p2p_msg(bool dir, struct peer_t *ev, u64 new_bytes)
{
	struct value_t *val;
	if (ev->type == AF_INET)
	{
		val = bpf_map_lookup_elem(&trackers_v4, &ev->ipv4);

		// No map entry yet, set it here
		if (!val)
		{
			struct value_t new_val = {};
			if (dir == true)
				new_val.bytes_out = new_bytes;
			else
				new_val.bytes_in = new_bytes;

			bpf_map_update_elem(&trackers_v4, &ev->ipv4, &new_val, BPF_NOEXIST);
			return 1;
		}
	}
	else if (ev->type == AF_INET6)
	{
		val = bpf_map_lookup_elem(&trackers_v6, &ev->ipv6);

		// No map entry yet, set it here
		if (!val)
		{

			struct value_t new_val = {};
			if (dir == true)
				new_val.bytes_out = new_bytes;
			else
				new_val.bytes_in = new_bytes;

			bpf_map_update_elem(&trackers_v6, &ev->ipv6, &new_val, BPF_NOEXIST);
			return 1;
		}
	}

	// Add to total bytes
	if (dir == true)
		__sync_fetch_and_add(&val->bytes_out, new_bytes);
	else
		__sync_fetch_and_add(&val->bytes_in, new_bytes);

	return 0;
}

// Kprobe for tracing tcp_sendmsg segments.
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(trace_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
	// Check if SKB is from geth
	if (!is_eth_pname(get_pname()))
		return 0;

	// Little endian
	u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	__be16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

	if (sport != p2p_port && dport != bpf_htons(ETH_P2P_PORT))
		return 0;

	u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	kuid_t sock_uid = BPF_CORE_READ(sk, sk_uid);

	if (family == AF_INET)
	{
		struct peer_v4_t peer_v4 = {.dport = bpf_ntohs(dport)};
		BPF_CORE_READ_INTO(&peer_v4.daddr, sk, __sk_common.skc_daddr);
		struct peer_t ev = {.type = AF_INET, .ipv4 = peer_v4};
		if (handle_p2p_msg(true, &ev, (u64)size) == 1)
			bpf_map_update_elem(&sockets, &sock_uid, &ev, BPF_NOEXIST);
	}
	else if (family == AF_INET6)
	{
		struct peer_v6_t peer_v6 = {.dport = bpf_ntohs(dport)};
		BPF_CORE_READ_INTO(&peer_v6.daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
		struct peer_t ev = {.type = AF_INET6, .ipv6 = peer_v6};
		if (handle_p2p_msg(true, &ev, (u64)size) == 1)
			bpf_map_update_elem(&sockets, &sock_uid, &ev, BPF_NOEXIST);
	}

	return 0;
}

// https://elixir.bootlin.com/linux/latest/source/net/ipv4/tcp.c#L1545
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(trace_tcp_cleanup_rbuf, struct sock *sk, int copied)
{
	// Check if SKB is from geth
	if (!is_eth_pname(get_pname()))
		return 0;

	if (copied <= 0)
		return 0;

	u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	__be16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

	kuid_t sock_uid = BPF_CORE_READ(sk, sk_uid);

	if (family == AF_INET)
	{
		struct peer_v4_t peer_v4 = {.dport = bpf_ntohs(dport)};
		BPF_CORE_READ_INTO(&peer_v4.daddr, sk, __sk_common.skc_daddr);
		struct peer_t ev = {.type = AF_INET, .ipv4 = peer_v4};
		if (handle_p2p_msg(false, &ev, (u64)copied) == 1)
			bpf_map_update_elem(&sockets, &sock_uid, &ev, BPF_NOEXIST);
	}
	else if (family == AF_INET6)
	{
		struct peer_v6_t peer_v6 = {.dport = bpf_ntohs(dport)};
		BPF_CORE_READ_INTO(&peer_v6.daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
		struct peer_t ev = {.type = AF_INET6, .ipv6 = peer_v6};
		if (handle_p2p_msg(false, &ev, (u64)copied) == 1)
			bpf_map_update_elem(&sockets, &sock_uid, &ev, BPF_NOEXIST);
	}

	return 0;
}

// We remove the socket from our socket map if the connection gets closed.
// https://elixir.bootlin.com/linux/latest/source/include/net/tcp_states.h#L12
SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(trace_inet_sock_set_state, struct sock *sk, int oldstate, int newstate)
{
	if (newstate == BPF_TCP_CLOSE || BPF_TCP_FIN_WAIT1)
	{
		kuid_t sock_uid = BPF_CORE_READ(sk, sk_uid);
		struct peer_t *val = bpf_map_lookup_elem(&sockets, &sock_uid);

		if (!val)
			return 0;

		// Delete socket from map
		bpf_map_delete_elem(&sockets, &sock_uid)

		if (val->type == AF_INET)
			bpf_map_delete_elem(&trackers_v4, &val->ipv4)
		else if (val->type == AF_INET6)
			bpf_map_delete_elem(&trackers_v6, &val->ipv6)

		return 0;
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
