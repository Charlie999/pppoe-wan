#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

#include "pppoe.h"

#define PROTO_8021Q 0x8100
#define PROTO_QINQ 0x88A8

#define PROTO_IP4 0x0800
#define PROTO_PPPOE_DISC 0x8863
#define PROTO_PPPOE_SESS 0x8864

#define PPPOE_SESS_MIN_LEN (sizeof(struct ethhdr) + sizeof(struct pppoehdr) + 4)

// TODO: add IPv6 support
// page size 4K so no jumbo frames (but 1508 should be OK)

SEC("xdp-decap")
int xdp_decap_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

    if (data + PPPOE_SESS_MIN_LEN < data_end) {
        struct ethhdr *eth_hdr = (struct ethhdr*)data;
        void *cur_ptr = data + sizeof(struct ethhdr);

        if (bpf_ntohs(eth_hdr->h_proto) == PROTO_8021Q) cur_ptr += 4; // cover 802.1Q and QinQ VLANs
        if (bpf_ntohs(eth_hdr->h_proto) == PROTO_QINQ) cur_ptr += 4;

        if (bpf_ntohs(eth_hdr->h_proto) != PROTO_PPPOE_SESS) return XDP_PASS; // return if not pppoe session data

        struct pppoehdr *pppoe_hdr = (struct pppoehdr*)cur_ptr;
        cur_ptr += sizeof(struct pppoehdr);

        if (pppoe_hdr->vt != 0x11 | pppoe_hdr->code != 0x00) return XDP_PASS; // Invalid PPPoE session packet. May as well drop.
        
        unsigned short ppp_proto = *(unsigned short*)cur_ptr;
        if (bpf_ntohs(ppp_proto) != PPP_PROTO_IP4) return XDP_PASS; // drop if not IP

        data = (void *)(long)(ctx->data + sizeof(struct pppoehdr) + 2);
        struct ethhdr *eth_hdr_new = (struct ethhdr*)data; // new ethernet header

        unsigned char src[6] = {eth_hdr->h_source[0], eth_hdr->h_source[1], eth_hdr->h_source[2], eth_hdr->h_source[3], eth_hdr->h_source[4], eth_hdr->h_source[5]};

        eth_hdr_new->h_dest[0] = eth_hdr->h_dest[0]; // this is OK mostly. dest is just before the new ethhdr
        eth_hdr_new->h_dest[1] = eth_hdr->h_dest[1]; // but this could be faster
        eth_hdr_new->h_dest[2] = eth_hdr->h_dest[2];
        eth_hdr_new->h_dest[3] = eth_hdr->h_dest[3];
        eth_hdr_new->h_dest[4] = eth_hdr->h_dest[4];
        eth_hdr_new->h_dest[5] = eth_hdr->h_dest[5];

        eth_hdr_new->h_source[0] = src[0];
        eth_hdr_new->h_source[1] = src[1];
        eth_hdr_new->h_source[2] = src[2];
        eth_hdr_new->h_source[3] = src[3];
        eth_hdr_new->h_source[4] = src[4];
        eth_hdr_new->h_source[5] = src[5];

        eth_hdr_new->h_proto = bpf_htons(PROTO_IP4);

        if (bpf_xdp_adjust_head(ctx, sizeof(struct pppoehdr) + 2) != 0) return XDP_ABORTED; // Failed to adjust header
    }

    return XDP_PASS; // New header added over the old PPPoE header, frame shrunk by 8.
}

char _license[] SEC("license") = "GPL";