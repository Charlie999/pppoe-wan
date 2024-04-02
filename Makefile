# build and test
all:
	/bin/clang -O2 -Wall -target bpf -c xdp-decap.c -o xdp-decap.o
	sudo ip link set tun1 xdpgeneric off || true
	sudo ip link set tun1 xdpgeneric obj xdp-decap.o sec xdp-decap

	/bin/clang -O2 -g -Wall -target bpf -c bpf-encap.c -o bpf-encap.o
	sudo tc qdisc del dev tun1 clsact || true
	sudo tc qdisc add dev tun1 clsact
	sudo tc qdisc del dev dummy0 clsact || true
	sudo tc qdisc add dev dummy0 clsact

	sudo tc filter add dev dummy0 egress bpf direct-action obj bpf-encap.o sec egress
	sudo tc filter show dev dummy0 egress

	sudo tc filter add dev tun1 ingress bpf direct-action obj bpf-encap.o sec ingress
	sudo tc filter show dev tun1 ingress