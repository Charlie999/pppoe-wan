#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define bpf_memcpy __builtin_memcpy

#include "pppoe.h"

#define PROTO_IP4 0x0800
#define PROTO_IP6 0x86DD

#define PROTO_INTERNAL_IP4 0xFFF0
#define PROTO_INTERNAL_IP6 0xFFF1

// copy inner IP header to ethhdr + PPPoE
// tcp mssfix is needed.
SEC("egress")
int _egress(struct __sk_buff *skb) {
	void *data = (void*)(long)skb->data;
    void *data_end  = (void*)(long)skb->data_end;

	struct ethhdr *eth = (struct ethhdr*)data;

	if (data + sizeof(struct ethhdr) > data_end) return TC_ACT_OK;
	if (bpf_ntohs(eth->h_proto) != PROTO_IP4 && bpf_ntohs(eth->h_proto) != PROTO_IP6) return TC_ACT_OK; 

	__u8 src_mac[ETH_ALEN] = {0x86,0x82,0xd6,0x96,0x80,0x52};
	__u8 dst_mac[ETH_ALEN] = {0x4e,0x2a,0x46,0x39,0xfb,0xe2};
	//bpf_memcpy(src_mac, eth->h_source, ETH_ALEN);
	//bpf_memcpy(dst_mac, eth->h_dest, ETH_ALEN);

	unsigned short pklen = skb->len - sizeof(struct ethhdr);
	unsigned short proto = bpf_ntohs(eth->h_proto);

    if (bpf_skb_change_head(skb, sizeof(struct pppoehdr_combined), 0)) return TC_ACT_SHOT; // add PPPoE header + PPP header (aka just proto field)

	if (skb->data + sizeof(struct pppoehdr_combined) + sizeof(struct ethhdr) > skb->data_end) return TC_ACT_OK; // please the verifier

	data = (void*)(long)skb->data; // new pointers
    data_end  = (void*)(long)skb->data_end;

	eth = (struct ethhdr*)data;
	struct pppoehdr_combined *pppoe_hdr = (struct pppoehdr_combined*)(data + sizeof(struct ethhdr));
	
	eth->h_proto = bpf_htons(PROTO_PPPOE_SESS);

	bpf_memcpy(eth->h_source, src_mac, ETH_ALEN);
	bpf_memcpy(eth->h_dest, dst_mac, ETH_ALEN);

	pppoe_hdr->hdr.vt = 0x11;
	pppoe_hdr->hdr.code = 0x00; // PPPoE session packet with data

	pppoe_hdr->hdr.sessid = bpf_htons(0x1);
	pppoe_hdr->hdr.len = bpf_htons(pklen + 2); // plus two because PPP as well.

	if (proto == PROTO_IP4) pppoe_hdr->proto = bpf_htons(PPP_PROTO_IP4);
	else pppoe_hdr->proto = bpf_htons(PPP_PROTO_IP6);

	if (skb->data_end - skb->data > 1400)
		bpf_printk("Packet too long! len=%lu\n", skb->data_end - skb->data);

	return bpf_redirect(33, 0); // put the packet out on the real if
}

SEC("ingress")
int _ingress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	struct ethhdr *eth = (struct ethhdr*)data;

	if (data + sizeof(struct ethhdr) > data_end) return TC_ACT_UNSPEC;

	switch (bpf_ntohs(eth->h_proto)) {
		case PROTO_INTERNAL_IP4:
			eth->h_proto = bpf_htons(PROTO_IP4);
			return bpf_redirect(61, BPF_F_INGRESS);
		case PROTO_INTERNAL_IP6:
			eth->h_proto = bpf_htons(PROTO_IP6);
			return bpf_redirect(61, BPF_F_INGRESS);
		default:
			return TC_ACT_OK;
	}
}

char LICENSE[] SEC("license") = "GPL";