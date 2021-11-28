struct ipv4_key_t
{
	u32 saddr;
	u32 daddr;
	u16 lport;
	u16 dport;
};

struct ipv6_key_t
{
	unsigned __int128 saddr;
	unsigned __int128 daddr;
	u16 lport;
	u16 dport;
	u64 __pad__;
};

struct ip_key_t
{
	u16 type; // v4 or v6
	union
	{
		struct ipv4_key_t ipv4;
		struct ipv6_key_t ipv6;
	};
};

struct value_t {
	u64 bytes_in;
	u64 bytes_out;
};