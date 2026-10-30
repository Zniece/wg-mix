/* SPDX-License-Identifier: MIT */
#ifndef __TYPEOBFS_H
#define __TYPEOBFS_H

/*
 * 自包含的最小定义：不依赖 <linux/bpf.h> / libbpf / BTF。
 * BPF 程序只使用 UAPI 稳定的 helper 与自带的报文头解析，
 * 因此不需要 CO-RE，也不需要在目标内核上生成 vmlinux.h。
 */

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define SEC(name) __attribute__((section(name), used))

#define TC_ACT_OK 0
#define XDP_PASS 2

/* UAPI 布局，直接用于 XDP 上下文；只读 data/data_end */
struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	__u32 ingress_ifindex;
	__u32 rx_queue_index;
	__u32 egress_ifindex;
};

/* map types */
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PERCPU_ARRAY 6

/* helper ids（UAPI 稳定值） */
#define BPF_FUNC_map_lookup_elem 1
#define BPF_FUNC_skb_store_bytes 9
#define BPF_FUNC_l4_csum_replace 11
#define BPF_FUNC_skb_load_bytes 26

/* bpf_l4_csum_replace flags */
#define BPF_F_MARK_MANGLED_0 (1ULL << 5)

/* ports map 的 value 位 */
#define PORT_ROLE_LOCAL 1
#define PORT_ROLE_PEER 2

/* stats 下标 */
enum {
	STAT_MATCHED = 0,
	STAT_REWRITTEN,
	STAT_XDP_MATCHED,
	STAT_XDP_REWRITTEN,
	STAT_MAX,
};

/* legacy map 定义，cilium/ebpf 与 libbpf 都认识 */
struct bpf_map_def {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
};

#endif /* __TYPEOBFS_H */
