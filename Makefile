# build and test
all:
	/bin/clang -O2 -g -Wall -target bpf -c xdp-decap.c -o xdp-decap.o
	/bin/clang -O2 -g -Wall -target bpf -c xdp-encap.c -o xdp-encap.o
	sudo ip link set tun1 xdpgeneric off || true
	sudo ip link set veth1-b xdpgeneric off || true
	gcc -O2 -Wall -o controller controller.c -lbpf -lxdp