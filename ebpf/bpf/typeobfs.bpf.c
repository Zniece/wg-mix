// SPDX-License-Identifier: MIT
//
// Rewrite the 4-byte WireGuard type in place: canonical -> wire on TC
// egress, wire -> canonical on XDP ingress. MACs remain canonical.
#include "typeobfs.h"

/* 只作为不透明指针传递，不访问字段，避免依赖 UAPI 头 */
struct __sk_buff;

static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
	(void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to,
				  __u32 len) = (void *)BPF_FUNC_skb_load_bytes;
static long (*bpf_skb_store_bytes)(void *skb, __u32 offset, const void *from,
				   __u32 len, __u64 flags) =
	(void *)BPF_FUNC_skb_store_bytes;
static long (*bpf_l4_csum_replace)(void *skb, __u32 offset, __u64 from,
				   __u64 to, __u64 flags) =
	(void *)BPF_FUNC_l4_csum_replace;

struct bpf_map_def SEC("maps") wire_types = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 4,
};

/* port -> local/peer role bitmask */
struct bpf_map_def SEC("maps") ports = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 128,
};

struct bpf_map_def SEC("maps") stats = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = STAT_MAX,
};

/* 让 u32 的内存字节序与报文中的 4 字节完全一致，避免大小端分支 */
union u32bytes {
	__u32 v;
	__u8 b[4];
};

static __attribute__((always_inline)) void bump(__u32 key)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &key);
	if (v)
		*v += 1;
}

/*
 * 找到 UDP 头偏移、端口与 checksum 字段。
 * 只处理最常见的 eth / vlan / ipv4 / ipv6(+部分扩展头) / udp。
 * 返回 0 成功，-1 跳过。
 */
static __attribute__((always_inline)) int parse_l4(struct __sk_buff *skb,
						   __u32 *l4off, __u16 *sport,
						   __u16 *dport, __u16 *check)
{
	__u8 eth[14];
	if (bpf_skb_load_bytes(skb, 0, eth, sizeof(eth)) < 0)
		return -1;

	__u16 proto = ((__u16)eth[12] << 8) | eth[13];
	__u32 off = 14;

#pragma unroll
	for (int i = 0; i < 2; i++) {
		if (proto != 0x8100 && proto != 0x88a8)
			break;
		__u8 tag[4];
		if (bpf_skb_load_bytes(skb, off, tag, sizeof(tag)) < 0)
			return -1;
		proto = ((__u16)tag[2] << 8) | tag[3];
		off += 4;
	}

	__u8 ver;
	if (bpf_skb_load_bytes(skb, off, &ver, 1) < 0)
		return -1;

	if ((ver >> 4) == 4) {
		__u8 ip[20];
		if (bpf_skb_load_bytes(skb, off, ip, sizeof(ip)) < 0)
			return -1;
		__u32 ihl = (ip[0] & 0x0f) * 4;
		if (ihl < 20)
			return -1;
		if (ip[9] != 17) /* UDP */
			return -1;
		/* 非首片没有 UDP 头 */
		if ((ip[6] & 0x1f) != 0 || ip[7] != 0)
			return -1;
		*l4off = off + ihl;
	} else if ((ver >> 4) == 6) {
		__u8 ip6[40];
		if (bpf_skb_load_bytes(skb, off, ip6, sizeof(ip6)) < 0)
			return -1;
		__u8 next = ip6[6];
		__u32 p = off + 40;
#pragma unroll
		for (int i = 0; i < 4; i++) {
			if (next != 0 && next != 43 && next != 60)
				break;
			__u8 ext[8];
			if (bpf_skb_load_bytes(skb, p, ext, sizeof(ext)) < 0)
				return -1;
			__u32 hlen = ((__u32)ext[1] + 1) * 8;
			next = ext[0];
			p += hlen;
		}
		if (next != 17)
			return -1;
		*l4off = p;
	} else {
		return -1;
	}

	__u8 udp[8];
	if (bpf_skb_load_bytes(skb, *l4off, udp, sizeof(udp)) < 0)
		return -1;
	*sport = ((__u16)udp[0] << 8) | udp[1];
	*dport = ((__u16)udp[2] << 8) | udp[3];
	*check = ((__u16)udp[6] << 8) | udp[7];
	return 0;
}

SEC("tc")
int typeobfs_egress(struct __sk_buff *skb)
{
	__u32 l4off;
	__u16 sport, dport, check;
	if (parse_l4(skb, &l4off, &sport, &dport, &check) < 0)
		return TC_ACT_OK;

	/* egress：sport 本地或 dport 对端。先查 dport，命中就不查 sport */
	__u32 dk = dport, sk = sport;
	__u32 *dv = bpf_map_lookup_elem(&ports, &dk);
	int match = 0;
	if (dv && (*dv & PORT_ROLE_PEER)) {
		match = 1;
	} else {
		__u32 *sv = bpf_map_lookup_elem(&ports, &sk);
		if (sv && (*sv & PORT_ROLE_LOCAL))
			match = 1;
	}
	if (!match)
		return TC_ACT_OK;
	bump(STAT_MATCHED);

	/* 读报文头 4 字节，按 little-endian 解释成 canonical type */
	__u32 toff = l4off + 8;
	__u8 t[4];
	if (bpf_skb_load_bytes(skb, toff, t, sizeof(t)) < 0)
		return TC_ACT_OK;

	__u32 canon = ((__u32)t[0]) | ((__u32)t[1] << 8) |
		      ((__u32)t[2] << 16) | ((__u32)t[3] << 24);
	if (canon < 1 || canon > 4)
		return TC_ACT_OK;

	__u32 key = canon - 1;
	__u32 *wire = bpf_map_lookup_elem(&wire_types, &key);
	if (!wire || *wire == 0)
		return TC_ACT_OK;

	__u32 w = *wire;
	__u8 nt[4];
	nt[0] = w & 0xff;
	nt[1] = (w >> 8) & 0xff;
	nt[2] = (w >> 16) & 0xff;
	nt[3] = (w >> 24) & 0xff;

	union u32bytes from, to;
	from.b[0] = t[0];
	from.b[1] = t[1];
	from.b[2] = t[2];
	from.b[3] = t[3];
	to.b[0] = nt[0];
	to.b[1] = nt[1];
	to.b[2] = nt[2];
	to.b[3] = nt[3];

	if (bpf_skb_store_bytes(skb, toff, nt, sizeof(nt), 0) < 0)
		return TC_ACT_OK;

	/*
	 * size=4（低 4 位）；不设 BPF_F_PSEUDO_HDR，因为改的是载荷。
	 * CHECKSUM_PARTIAL 时由硬件对最终报文重算，helper 只更新
	 * CHECKSUM_NONE 的字段；check==0 用 MARK_MANGLED_0 保留。
	 */
	__u64 flags = sizeof(__u32);
	if (check == 0)
		flags |= BPF_F_MARK_MANGLED_0;
	bpf_l4_csum_replace(skb, l4off + 6, from.v, to.v, flags);

	bump(STAT_REWRITTEN);
	return TC_ACT_OK;
}

/*
 * XDP ingress：把线上 wire Type 还原成 canonical，并增量修正 UDP 校验和。
 * 直接包访问，不依赖 skb helper；只处理 eth/vlan/ipv4/ipv6/udp。
 */
static __attribute__((always_inline)) int xdp_parse(struct xdp_md *ctx,
						    __u32 *l4off_out,
						    __u16 *sport, __u16 *dport,
						    __u16 *check)
{
	__u8 *data = (void *)(long)ctx->data;
	__u8 *data_end = (void *)(long)ctx->data_end;

	if (data + 14 > data_end)
		return -1;
	__u16 proto = ((__u16)data[12] << 8) | data[13];
	__u32 off = 14;

#pragma unroll
	for (int i = 0; i < 2; i++) {
		if (proto != 0x8100 && proto != 0x88a8)
			break;
		if (data + off + 4 > data_end)
			return -1;
		proto = ((__u16)data[off + 2] << 8) | data[off + 3];
		off += 4;
	}

	if (data + off + 1 > data_end)
		return -1;
	__u8 ver = data[off];

	if ((ver >> 4) == 4) {
		if (data + off + 20 > data_end)
			return -1;
		__u32 ihl = (data[off] & 0x0f) * 4;
		if (ihl < 20)
			return -1;
		if (data[off + 9] != 17)
			return -1;
		if ((data[off + 6] & 0x1f) != 0 || data[off + 7] != 0)
			return -1;
		*l4off_out = off + ihl;
	} else if ((ver >> 4) == 6) {
		if (data + off + 40 > data_end)
			return -1;
		__u8 next = data[off + 6];
		__u32 q = off + 40;
#pragma unroll
		for (int i = 0; i < 4; i++) {
			if (next != 0 && next != 43 && next != 60)
				break;
			/* 用指针做边界检查，避免标量偏移丢失 verifier 范围 */
			__u8 *p = data + q;
			if (p + 8 > data_end)
				return -1;
			__u8 nxt = p[0];
			q += ((__u32)p[1] + 1) * 8;
			next = nxt;
		}
		if (next != 17)
			return -1;
		*l4off_out = q;
	} else {
		return -1;
	}

	__u32 l4 = *l4off_out;
	if (data + l4 + 8 > data_end)
		return -1;
	*sport = ((__u16)data[l4] << 8) | data[l4 + 1];
	*dport = ((__u16)data[l4 + 2] << 8) | data[l4 + 3];
	*check = ((__u16)data[l4 + 6] << 8) | data[l4 + 7];
	return 0;
}

/* 4 项数组反查，手工展开；不引入额外的 hash map */
static __attribute__((always_inline)) __u32 wire_to_canon(__u32 wire)
{
	__u32 k0 = 0, k1 = 1, k2 = 2, k3 = 3;
	__u32 *w;

	w = bpf_map_lookup_elem(&wire_types, &k0);
	if (w && *w == wire)
		return 1;
	w = bpf_map_lookup_elem(&wire_types, &k1);
	if (w && *w == wire)
		return 2;
	w = bpf_map_lookup_elem(&wire_types, &k2);
	if (w && *w == wire)
		return 3;
	w = bpf_map_lookup_elem(&wire_types, &k3);
	if (w && *w == wire)
		return 4;
	return 0;
}

SEC("xdp")
int typeobfs_ingress(struct xdp_md *ctx)
{
	__u8 *data = (void *)(long)ctx->data;
	__u8 *data_end = (void *)(long)ctx->data_end;

	__u32 l4;
	__u16 sport, dport, check;
	if (xdp_parse(ctx, &l4, &sport, &dport, &check) < 0)
		return XDP_PASS;

	/* ingress：dport 本地或 sport 对端。先查 dport，命中就不查 sport */
	__u32 dk = dport, sk = sport;
	__u32 *dv = bpf_map_lookup_elem(&ports, &dk);
	int match = 0;
	if (dv && (*dv & PORT_ROLE_LOCAL)) {
		match = 1;
	} else {
		__u32 *sv = bpf_map_lookup_elem(&ports, &sk);
		if (sv && (*sv & PORT_ROLE_PEER))
			match = 1;
	}
	if (!match)
		return XDP_PASS;
	bump(STAT_XDP_MATCHED);

	__u32 toff = l4 + 8;
	if (data + toff + 4 > data_end)
		return XDP_PASS;

	__u8 t[4];
	t[0] = data[toff];
	t[1] = data[toff + 1];
	t[2] = data[toff + 2];
	t[3] = data[toff + 3];
	__u32 wire = ((__u32)t[0]) | ((__u32)t[1] << 8) |
		     ((__u32)t[2] << 16) | ((__u32)t[3] << 24);

	__u32 c = wire_to_canon(wire);
	if (c == 0)
		return XDP_PASS;
	__u8 n[4];
	n[0] = c & 0xff;
	n[1] = (c >> 8) & 0xff;
	n[2] = (c >> 16) & 0xff;
	n[3] = (c >> 24) & 0xff;

	data[toff] = n[0];
	data[toff + 1] = n[1];
	data[toff + 2] = n[2];
	data[toff + 3] = n[3];

	/* IPv4 UDP check==0 表示无校验和，必须保持 0 */
	if (check != 0) {
		__u16 old0 = ((__u16)t[0] << 8) | t[1];
		__u16 old1 = ((__u16)t[2] << 8) | t[3];
		__u16 new0 = ((__u16)n[0] << 8) | n[1];
		__u16 new1 = ((__u16)n[2] << 8) | n[3];

		/* RFC 1624: ~(~HC + ~m + m')，两个 16-bit 字 */
		__u32 sum = (~(__u32)check) & 0xffff;
		sum += (~(__u32)old0) & 0xffff;
		sum += (__u32)new0;
		sum += (~(__u32)old1) & 0xffff;
		sum += (__u32)new1;
		sum = (sum & 0xffff) + (sum >> 16);
		sum = (sum & 0xffff) + (sum >> 16);
		__u16 ncheck = ~(__u16)sum;

		__u8 *cs = data + l4 + 6;
		if (cs + 2 > data_end)
			return XDP_PASS;
		cs[0] = ncheck >> 8;
		cs[1] = ncheck & 0xff;
	}

	bump(STAT_XDP_REWRITTEN);
	return XDP_PASS;
}

char _license[] SEC("license") = "MIT";
