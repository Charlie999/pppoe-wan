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

//TODO: ARPv6!
SEC("xdp-encap")
int xdp_encap_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

    if (data + sizeof(struct ethhdr) > data_end) goto end;
    struct ethhdr *eth = (struct ethhdr*)data;

    // this dearly needs flow optimization!

    int zero = 0;
    struct control_map *ctnl = bpf_map_lookup_elem(&ctnl_map, &zero);
    if (!ctnl) goto end;

    if (data + sizeof(struct ethhdr) + sizeof(struct arphdr) + sizeof(struct arp_v4_tail) <= data_end && eth->h_proto == bpf_htons(PROTO_ARP)) { // ARP handler 
        // responds saying every IP in existence is at the port MAC.
        // ip route add default via 192.0.2.1 dev eth0
        struct arphdr *arp = (struct arphdr*)(data + sizeof(struct ethhdr));
        struct arp_v4_tail *tail = (struct arp_v4_tail*)(data + sizeof(struct ethhdr) + sizeof(struct arphdr));

        if (arp->ar_pro != bpf_htons(PROTO_IP4)) goto end; // yes, we need v6!

        arp->ar_op = bpf_htons(ARPOP_REPLY);

        // store old tail
        struct arp_v4_tail old = {};
        __builtin_memcpy(&old, tail, sizeof(old));

        __builtin_memcpy(&(tail->ip_target), &(old.ip_sender), sizeof(old.ip_sender));
        __builtin_memcpy(&(tail->mac_target), &(old.mac_sender), ETH_ALEN); // they are next to each other in ram and this could be one copy

        __builtin_memcpy(&(tail->ip_sender), &(old.ip_target), sizeof(old.ip_target));
        __builtin_memcpy(&(tail->mac_sender), ctnl->port_targ_mac, ETH_ALEN);

        __builtin_memcpy(&(eth->h_dest), &(eth->h_source), ETH_ALEN);
        __builtin_memcpy(&(eth->h_source), ctnl->port_targ_mac, ETH_ALEN);

        return XDP_TX;
    } else if (eth->h_proto == bpf_htons(PROTO_IP4) || eth->h_proto == bpf_htons(PROTO_IP6)) { // IP4/6->IPoPPPoE handler (encap)
        if (ctnl->pppoe_sessid == PPPOE_NOT_VALID) goto end; // don't send data out when invalid session (we don't know MACs, session IDs etc)

        unsigned long pklen = (data_end - data) - sizeof(struct ethhdr);
        uint16_t proto = bpf_ntohs(eth->h_proto);

        if (bpf_xdp_adjust_head(ctx, -((int64_t)sizeof(struct pppoehdr_combined))) != 0UL) return XDP_ABORTED;
        if (ctx->data + sizeof(struct pppoehdr_combined) + sizeof(struct ethhdr) > ctx->data_end) return XDP_ABORTED; // please the verifier

        data_end = (void *)(long)ctx->data_end;
	    data = (void *)(long)ctx->data;

        eth = (struct ethhdr*)data;
        __builtin_memcpy(&(eth->h_source), ctnl->port_ont_mac, ETH_ALEN);
        __builtin_memcpy(&(eth->h_dest), ctnl->ont_mac, ETH_ALEN);
        eth->h_proto = bpf_htons(PROTO_PPPOE_SESS);

        struct pppoehdr_combined *pppoe = (struct pppoehdr_combined*)(data + sizeof(struct ethhdr));

        pppoe->hdr.vt = 0x11;
        pppoe->hdr.code = 0x00; // PPPoE session packet with data

        pppoe->hdr.sessid = bpf_htons(ctnl->pppoe_sessid);
        pppoe->hdr.len = bpf_htons(pklen + 2); // plus two because PPP as well.

        if (proto == PROTO_IP4) pppoe->proto = bpf_htons(PPP_PROTO_IP4);
        else pppoe->proto = bpf_htons(PPP_PROTO_IP6);

        return bpf_redirect(ctnl->ifindex_ont, 0);
    }

end:
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
