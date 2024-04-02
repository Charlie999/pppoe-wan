#ifndef PPPOE_H
#define PPPOE_H

#define PPP_PROTO_IP4 0x0021
#define PPP_PROTO_IP6 0x0057

#define PROTO_PPPOE_DISC 0x8863
#define PROTO_PPPOE_SESS 0x8864

struct pppoehdr { // PPPoE base header
    unsigned char vt; // version, type
    unsigned char code; // code
    unsigned short sessid; // session ID
    unsigned short len; // length
} __attribute__((packed));

struct pppoehdr_combined { // PPPoE header including PPP header
    struct pppoehdr hdr;
    unsigned short proto;
} __attribute__((packed));

#endif