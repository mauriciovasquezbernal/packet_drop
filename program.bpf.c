// Copyright 2025 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/swab.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>

struct v4_lpm_key {
	__u32 prefixlen;
	__u32 addr;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct v4_lpm_key);
	__type(value, __u32);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 1024);
} drop_list SEC(".maps");

enum direction {
	INGRESS = 0,
	EGRESS = 1,
};

int drop(struct __sk_buff *skb, enum direction direction) {
	void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;
	__u32 ip_addr;

	// Check if the packet is not malformed
	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end)
		return TC_ACT_SHOT;

	// Check that this is an IP packet
	if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return TC_ACT_UNSPEC;

	// Check if the packet is not malformed
	struct iphdr *ip = data + sizeof(struct ethhdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
		return TC_ACT_SHOT;

	if (direction == INGRESS) {
		bpf_printk("ingress: src:%pi4 -> dst: %pi4", &ip->saddr, &ip->daddr);
		ip_addr = ip->saddr;
	} else {
		bpf_printk("egress: src:%pi4 -> dst: %pi4", &ip->saddr, &ip->daddr);
		ip_addr = ip->daddr;
	}

	struct v4_lpm_key key = {
		.prefixlen = 32,
		.addr = ip_addr,
	};
	__u32 *value = bpf_map_lookup_elem(&drop_list, &key);
	if (value) {
		bpf_printk("dropping packet");
		return TC_ACT_SHOT;
	}

	return TC_ACT_UNSPEC;
}

SEC("classifier/egress/drop")
int egress_drop(struct __sk_buff *skb) {
	return drop(skb, EGRESS);
}

SEC("classifier/ingress/drop")
int ingress_drop(struct __sk_buff *skb) {
	return drop(skb, INGRESS);
}

char __license[] SEC("license") = "GPL";
