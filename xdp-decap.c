#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

#include "pppoe.h"

#define PROTO_8021Q 0x8100
#define PROTO_QINQ 0x88A8

#define PROTO_IP4 0x0800
#define PROTO_IP6 0x86DD

#define PROTO_INTERNAL_IP4 0xFFF0
#define PROTO_INTERNAL_IP6 0xFFF1

#define PPPOE_SESS_MIN_LEN (sizeof(struct ethhdr) + sizeof(struct pppoehdr) + 4)

// page size 4K so no jumbo frames (but 1508 should be OK)
// decap and ready the packet for tc bpf

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

        if (pppoe_hdr->vt != 0x11 | pppoe_hdr->code != 0x00) return XDP_PASS; // pass if not payload? not sure if any valid IP packets come under this
        
        unsigned short ppp_proto = *(unsigned short*)cur_ptr;

        // use bpf_htons(PPP_PROTO_IP*) == ppp_proto instead? compiler may preprocess the constants
        if (bpf_ntohs(ppp_proto) != PPP_PROTO_IP4 && bpf_ntohs(ppp_proto) != PPP_PROTO_IP6) return XDP_PASS; // pass if not IP.

        data = (void *)(long)(ctx->data + sizeof(struct pppoehdr) + 2);
        struct ethhdr *eth_hdr_new = (struct ethhdr*)data; // new ethernet header

        unsigned char src[6] = {eth_hdr->h_source[0], eth_hdr->h_source[1], eth_hdr->h_source[2], eth_hdr->h_source[3], eth_hdr->h_source[4], eth_hdr->h_source[5]};

        __builtin_memcpy(eth_hdr_new->h_dest, eth_hdr->h_dest, ETH_ALEN);
        __builtin_memcpy(eth_hdr_new->h_source, src, ETH_ALEN);

        if (bpf_ntohs(ppp_proto) == PPP_PROTO_IP4) eth_hdr_new->h_proto = bpf_htons(PROTO_INTERNAL_IP4); // optimize with LUT? or combine with above ip4/6 control flow?
        else eth_hdr_new->h_proto = bpf_htons(PROTO_INTERNAL_IP6);

        if (bpf_xdp_adjust_head(ctx, sizeof(struct pppoehdr) + 2) != 0) return XDP_ABORTED; // Failed to adjust header

        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
