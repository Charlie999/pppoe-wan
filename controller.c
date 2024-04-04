#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <unistd.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <linux/if_arp.h>
#include <arpa/inet.h>
#include <signal.h>

#include "control.h"
#include "pppoe.h"

static volatile char run = 1;
static volatile int rawsock = -1;
static const char zeromac[6] = {0,0,0,0,0,0};

struct bpf_map_info map_info = {
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct control_map),
    .max_entries = 1,
};

struct xdp_program *load_bpf_to_if_attach(uint32_t ifindex, const char* section, const char* fname) {
    char msg[1024];

    struct xdp_program *ret = xdp_program__open_file(fname, section, NULL);
    int err = libxdp_get_error(ret);
    if (err) {
        libxdp_strerror(err, msg, sizeof(msg));
        fprintf(stderr, "xdp_program__open_file(): %s\n", msg);
        exit(errno);
    }

    err = xdp_program__attach(ret, ifindex, XDP_MODE_NATIVE, 0);
    if (err) {
        libxdp_strerror(err, msg, sizeof(msg));
        fprintf(stderr, "xdp_program__attach(): %s\n", msg);
        exit(errno);
    }

    return ret;
}

struct control_map populate_initial_if_info(const char* ifname_ont, const char* ifname_targ) {
    struct control_map ctnl;

    struct ifreq ifr;
    int iffd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (iffd<0) {
        perror("socket()");
        exit(errno);
    }

    strcpy(ifr.ifr_name, ifname_ont);
    if (ioctl(iffd, SIOCGIFHWADDR, &ifr) != 0) {
        perror("ioctl()");
        exit(errno);
    }
    memcpy(&(ctnl.port_ont_mac), ifr.ifr_addr.sa_data, sizeof(ctnl.port_ont_mac));
    strcpy(ifr.ifr_name, ifname_ont);
    if (ioctl(iffd, SIOCGIFINDEX, &ifr) != 0) {
        perror("ioctl()");
        exit(errno);
    }
    ctnl.ifindex_ont = ifr.ifr_ifindex;
    if (ioctl(iffd, SIOCGIFMTU, &ifr) != 0) {
        perror("ioctl()");
        exit(errno);
    }
    ctnl.ont_mtu = ifr.ifr_mtu;

    printf("ONT\tPORT MAC: ");
    for (int i=0;i<6;i++)
        printf("%02X ", ctnl.port_ont_mac[i]);
    printf(", IFINDEX %d, MTU %d\n", ctnl.ifindex_ont, ctnl.ont_mtu);

    //

    strcpy(ifr.ifr_name, ifname_targ);
    if (ioctl(iffd, SIOCGIFHWADDR, &ifr) != 0) {
        perror("ioctl()");
        exit(errno);
    }
    memcpy(&(ctnl.port_targ_mac), ifr.ifr_addr.sa_data, sizeof(ctnl.port_targ_mac));
    strcpy(ifr.ifr_name, ifname_targ);
    if (ioctl(iffd, SIOCGIFINDEX, &ifr) != 0) {
        perror("ioctl()");
        exit(errno);
    }
    ctnl.ifindex_targ = ifr.ifr_ifindex;

    printf("TARG\tPORT MAC: ");
    for (int i=0;i<6;i++)
        printf("%02X ", ctnl.port_targ_mac[i]);
    printf(", IFINDEX %d\n", ctnl.ifindex_targ);

    close(iffd);

    return ctnl;
}

void sigint(int dontcare) {
    fprintf(stderr, "\ncaught sigint\n");
    if (rawsock>=0) close(rawsock);
    run = 0;
}

int main(int argc, char** argv) {
    struct control_map ctnl = populate_initial_if_info("ens16d1.1000", "ens16d1.1001");
    ctnl.pppoe_sessid = PPPOE_NOT_VALID;

    ctnl.targ_mac[0] = 0xf4;
    ctnl.targ_mac[1] = 0x52;
    ctnl.targ_mac[2] = 0x14;
    ctnl.targ_mac[3] = 0x92;
    ctnl.targ_mac[4] = 0xc8;
    ctnl.targ_mac[5] = 0xe1;

    // load BPF progs
    struct xdp_program* decap = load_bpf_to_if_attach(ctnl.ifindex_ont, "xdp-decap", "xdp-decap.o");
    struct xdp_program* encap = load_bpf_to_if_attach(ctnl.ifindex_targ, "xdp-encap", "xdp-encap.o");

    printf("Attached XDP programs\n");

    int decap_mapfd = bpf_object__find_map_fd_by_name(xdp_program__bpf_obj(decap), "ctnl_map");
    if (decap_mapfd<0) {
        perror("bpf_object__find_map_fd_by_name()");
        goto fail;
    }

    int encap_mapfd = bpf_object__find_map_fd_by_name(xdp_program__bpf_obj(encap), "ctnl_map");
    if (encap_mapfd<0) {
        perror("bpf_object__find_map_fd_by_name()");
        goto fail;
    }

    // set config info

    int zero = 0;
    int err = bpf_map_update_elem(decap_mapfd, &zero, &ctnl, 0);
    if (err<0) {
        perror("bpf_map_update_elem()");
        goto fail;
    }

    err = bpf_map_update_elem(encap_mapfd, &zero, &ctnl, 0);
    if (err<0) {
        perror("bpf_map_update_elem()");
        goto fail;
    }

    __sighandler_t sig = signal(SIGINT, sigint);
    if (sig == SIG_ERR) {
        perror("signal()");
        goto fail;
    }

    printf("Waiting on ONT TX....\n");

    rawsock = socket(AF_PACKET, SOCK_DGRAM, htons(PROTO_PPPOE_SESS));
    if (rawsock < 0) {
        perror("socket()");
        goto fail;
    }

    struct sockaddr_ll ont_sockaddr = {.sll_family = AF_PACKET, .sll_ifindex = ctnl.ifindex_ont, .sll_protocol = htons(PROTO_PPPOE_SESS)};
    if (bind(rawsock, (struct sockaddr*)&ont_sockaddr, sizeof(ont_sockaddr))<0) {
        perror("bind()");
        goto fail;
    }

    uint8_t *buf = (uint8_t*)malloc(ctnl.ont_mtu);

    struct sockaddr_ll addr;
    uint32_t alen = 0;
    while (run) { // learn ONT IP
        int len = recvfrom(rawsock, buf, ctnl.ont_mtu, 0, (struct sockaddr*)&addr, &alen);
        struct pppoehdr_combined *pppoe = (struct pppoehdr_combined*)buf;
        if (len<0) {
            perror("recvfrom()");
            free(buf);
            goto fail;
        }
        if (memcmp(addr.sll_addr, ctnl.port_ont_mac, ETH_ALEN) != 0 && memcmp(addr.sll_addr, zeromac, 6) != 0) {
            memcpy(ctnl.ont_mac, addr.sll_addr, ETH_ALEN);
            ctnl.pppoe_sessid = ntohs(pppoe->hdr.sessid);
            printf("Learnt\tONT MAC: ");
            for (int i=0;i<6;i++) printf("%02X ", ctnl.ont_mac[i]);
            printf("\nLearnt\tPPPoE sessid = 0x%04X\n", ctnl.pppoe_sessid);
            
            err = bpf_map_update_elem(decap_mapfd, &zero, &ctnl, 0);
            if (err<0) {
                perror("bpf_map_update_elem()");
                goto fail;
            }

            err = bpf_map_update_elem(encap_mapfd, &zero, &ctnl, 0);
            if (err<0) {
                perror("bpf_map_update_elem()");
                goto fail;
            }

            break;
        }
    }

    free(buf);
    close(rawsock);

    printf("bridge should now be up\n");

    while(run){usleep(10000);}

    xdp_program__detach(decap, ctnl.ifindex_ont, XDP_MODE_NATIVE, 0);
    xdp_program__detach(encap, ctnl.ifindex_targ, XDP_MODE_NATIVE, 0);

    return EXIT_SUCCESS;

    fail:
    xdp_program__detach(decap, ctnl.ifindex_ont, XDP_MODE_NATIVE, 0);
    xdp_program__detach(encap, ctnl.ifindex_targ, XDP_MODE_NATIVE, 0);
    return errno;
}