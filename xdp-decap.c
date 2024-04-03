#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

#include "pppoe.h"
#include "arp.h"
#include "control.h"

#define PROTO_8021Q 0x8100
#define PROTO_QINQ 0x88A8

#define PROTO_IP4 0x0800
#define PROTO_IP6 0x86DD
#define PROTO_ARP 0x0806

#define PROTO_INTERNAL_IP4 0xFFF0
#define PROTO_INTERNAL_IP6 0xFFF1

#define PPPOE_SESS_MIN_LEN (sizeof(struct ethhdr) + sizeof(struct pppoehdr) + 4)

// page size 4K so no jumbo frames (but 1508 should be OK)
// applies to all pppoe session IDs (no filtering) so needs to be on vlan with ont directly

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, uint32_t);
        __type(value, struct control_map);
        __uint(max_entries, 1);
} ctnl_map SEC(".maps");

SEC("xdp-decap")
int xdp_decap_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

    int zero = 0;
    struct control_map *ctnl = bpf_map_lookup_elem(&ctnl_map, &zero);
    if (!ctnl) return XDP_PASS;

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

        if (data + sizeof(struct ethhdr) > data_end) return XDP_ABORTED; // please the verifier

        struct ethhdr *eth_hdr_new = (struct ethhdr*)data; // new ethernet header

        __builtin_memcpy(eth_hdr_new->h_dest, ctnl->targ_mac, ETH_ALEN);
        __builtin_memcpy(eth_hdr_new->h_source, ctnl->port_targ_mac, ETH_ALEN);

        if (bpf_ntohs(ppp_proto) == PPP_PROTO_IP4) eth_hdr_new->h_proto = bpf_htons(PROTO_IP4); // optimize with LUT? or combine with above ip4/6 control flow?
        else eth_hdr_new->h_proto = bpf_htons(PROTO_IP6);

        if (bpf_xdp_adjust_head(ctx, sizeof(struct pppoehdr) + 2) != 0UL) return XDP_ABORTED; // Failed to adjust header

        return bpf_redirect(ctnl->ifindex_targ, 0);
    }

    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";
