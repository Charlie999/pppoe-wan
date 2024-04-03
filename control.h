#ifndef CONTROL_H
#define CONTROL_H

#include <stdint.h>

#define PPPOE_NOT_VALID 0

struct control_map {
    int ifindex_ont, ifindex_targ;
    uint8_t port_ont_mac[6], ont_mac[6];
    uint8_t port_targ_mac[6], targ_mac[6];
    uint16_t pppoe_sessid;
    uint16_t ont_mtu;
};

#endif