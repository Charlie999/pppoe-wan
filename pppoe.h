#ifndef PPPOE_H
#define PPPOE_H

#define PPP_PROTO_IP4 0x0021

struct pppoehdr { // PPPoE base header
    unsigned char vt; // version, type
    unsigned char code; // code
    unsigned short sessid; // session ID
    unsigned short len; // length
} __attribute__((packed));

#endif