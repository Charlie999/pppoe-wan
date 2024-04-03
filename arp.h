#ifndef ARP_H
#define ARP_H

#include <stdint.h>

struct arp_v4_tail { // 20-byte ARP payload for v4 request/response
    uint8_t mac_sender[6];
    uint32_t ip_sender;
    uint8_t mac_target[6];
    uint32_t ip_target;
} __attribute__((packed));

#endif