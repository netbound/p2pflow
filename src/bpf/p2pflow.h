struct peer_v4_t
{
	u32 saddr;
	u32 daddr;
	u16 lport;
	u16 dport;
};

struct peer_v6_t
{
	unsigned __int128 saddr;
	unsigned __int128 daddr;
	u16 lport;
	u16 dport;
	u64 __pad__;
};

struct peer_t
{
	u16 type; // v4 or v6
	union
	{
		struct peer_v4_t ipv4;
		struct peer_v6_t ipv6;
	};
};

struct value_t {
	u64 bytes_in;
	u64 bytes_out;
};