#include "vmlinux.h"
#include "p2pflow.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define HOSTNAME_LEN 84
#define ETH_HLEN 14

#define ETH_P_IP 0x0800

#define AF_INET 2	/* IP protocol family.  */
#define AF_INET6 10 /* IP version 6.  */

#define ETH_P2P_PORT 30303

// rodata section, changed in userspace before loading BPF program
const volatile u16 p2p_port = ETH_P2P_PORT;
const volatile char process_name[20] = "geth";

// dummy instances to generate skeleton types
struct ipv4_key_t _ipv4 = {};
struct ipv6_key_t _ipv6 = {};
struct value_t _val = {};

struct bpf_map_def SEC("maps") trackers_v4 = {
	.type = BPF_MAP_TYPE_HASH,
	.max_entries = 4096,
	.key_size = sizeof(struct ipv4_key_t),
	.value_size = sizeof(struct value_t) // bytes sent/recvd
};

struct bpf_map_def SEC("maps") trackers_v6 = {
	.type = BPF_MAP_TYPE_HASH,
	.max_entries = 4096,
	.key_size = sizeof(struct ipv6_key_t),
	.value_size = sizeof(struct value_t) // bytes sent/recvd
};

struct bpf_map_def SEC("maps") sockets = {
	.type = BPF_MAP_TYPE_HASH,
	.max_entries = 4096,
	.key_size = sizeof(kuid_t),
	.value_size = sizeof(struct ip_key_t)};

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

static __always_inline bool is_eth_pname(char *str)
{
	char comparand[4];
	bpf_probe_read(&comparand, sizeof(comparand), str);
	char compare[] = "geth";
	for (int i = 0; i < 4; ++i)
		if (compare[i] != comparand[i])
			return false;
	return true;
}

// Returns 1 if new entry was created, 0 for update
static __always_inline int handle_p2p_msg(struct ip_key_t *ev, u64 new_bytes)
{
	if (ev->type == AF_INET)
	{
		struct value_t *val = bpf_map_lookup_elem(&trackers_v4, &ev->ipv4);

		// No map entry yet, set it here
		if (!val)
		{
			struct value_t new_val = {.bytes_out = new_bytes};
			bpf_map_update_elem(&trackers_v4, &ev->ipv4, &new_val, BPF_NOEXIST);
			return 1;
		}

		// Add to total bytes
		__sync_fetch_and_add(&val->bytes_out, new_bytes);
	}
	else if (ev->type == AF_INET6)
	{
		struct value_t *val = bpf_map_lookup_elem(&trackers_v6, &ev->ipv6);

		// No map entry yet, set it here
		if (!val)
		{
			struct value_t new_val = {.bytes_out = new_bytes};
			bpf_map_update_elem(&trackers_v6, &ev->ipv6, &new_val, BPF_NOEXIST);
			return 1;
		}

		// Add to total bytes
		__sync_fetch_and_add(&val->bytes_out, new_bytes);
	}

	return 0;
}

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
		struct ipv4_key_t ipv4_key = {.dport = bpf_ntohs(dport)};
		BPF_CORE_READ_INTO(&ipv4_key.saddr, sk, __sk_common.skc_rcv_saddr);
		BPF_CORE_READ_INTO(&ipv4_key.daddr, sk, __sk_common.skc_daddr);
		BPF_CORE_READ_INTO(&ipv4_key.lport, sk, __sk_common.skc_num);
		struct ip_key_t ev = {.type = AF_INET, .ipv4 = ipv4_key};
		if (handle_p2p_msg(&ev, (u64)size) == 1)
			bpf_map_update_elem(&sockets, &sock_uid, &ev, BPF_NOEXIST);
	}
	else if (family == AF_INET6)
	{
		struct ipv6_key_t ipv6_key = {.dport = bpf_ntohs(dport)};
		BPF_CORE_READ_INTO(&ipv6_key.saddr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&ipv6_key.daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&ipv6_key.lport, sk, __sk_common.skc_num);
		struct ip_key_t ev = {.type = AF_INET6, .ipv6 = ipv6_key};
		if (handle_p2p_msg(&ev, (u64)size) == 1)
			bpf_map_update_elem(&sockets, &sock_uid, &ev, BPF_NOEXIST);
	}

	return 0;
}

SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(inet_sock_set_state_exit, struct sock *sk, int oldstate, int newstate)
{
	if (newstate == BPF_TCP_CLOSE)
	{
		kuid_t sock_uid = BPF_CORE_READ(sk, sk_uid);
		struct ip_key_t *val = bpf_map_lookup_elem(&sockets, &sock_uid);

		if (!val)
			return 0;

		bpf_map_delete_elem(&sockets, &sock_uid);

		if (val->type == AF_INET)
		{
			bpf_map_delete_elem(&trackers_v4, &val->ipv4);
			bpf_printk("Closed ipv4 connection: %d", val->ipv4.daddr);
		}
		else if (val->type == AF_INET6)
		{
			bpf_map_delete_elem(&trackers_v6, &val->ipv6);
			bpf_printk("Closed ipv6 connection: %d", val->ipv6.daddr);
		}

		return 0;
	}

	return 0;
}

// TODO: ingress bytes
// SEC("tp_btf/netif_receive_skb")
// int BPF_PROG(netif_receive_skb, struct sk_buff *skb)
// {
// 	// Check if SKB is from geth
// 	if (!is_eth_pname(get_pname()))
// 		return 0;

// 	struct ethhdr *eth = (struct ethhdr *)skb->head + skb->mac_header;
// 	// bpf_printk("%d", eth->h_proto);
// 	if (eth->h_proto != bpf_htons(ETH_P_IP))
// 		return 0;

// 	struct iphdr *ip = (struct iphdr *)skb->head + skb->network_header;
// 	if (ip->protocol != IPPROTO_TCP)
// 		return 0;

// 	struct tcphdr *tcp = (struct tcphdr *)skb->head + skb->transport_header;

// 	if (tcp->dest == bpf_htons(p2p_port) || tcp->source == bpf_htons(p2p_port))
// 	{
// 		return 0;
// 	}

// 	return 0;
// }

char LICENSE[] SEC("license") = "GPL";