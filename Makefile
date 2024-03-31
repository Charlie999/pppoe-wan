# build and test
all:
	clang -O2 -g -Wall -target bpf -c xdp-decap.c -o xdp-decap.o
	sudo ip link set tun1 xdpgeneric off || true
	sudo ip link set tun1 xdpgeneric obj xdp-decap.o sec xdp-decap