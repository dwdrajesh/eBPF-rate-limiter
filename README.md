# eBPF-rate-limiter
eBPF based sliding window rate limiter with load balancer
(Note: This is based on the tutorial given by Liz Rice in the online session for building a basic load balancer. )


This is for simulating a sliding window based rate limiter with the load balancer using eBPF and using the XDP module in kernel to inspect the incoming packets on the interface. 
How to:
- Since running natively on MAC M2 ARM based processor had some issues, I chose to use limactl to launch an Ubuntu VM that has all the 4 containers, namely the load balancer, client and 2 backend servers.

Steps:
- Launch an Ubuntu VM using limactl (if not installed already, here are the steps:
https://medium.com/@harry-touloupas/when-mac-m1-m2-met-ebpf-a-tale-of-compatibility-6b9a6bc53f3e)

- cd to the directory and launch:
- cd my_docs/ebpf/ebpf_mac_arm/
limactl start --name=ebpf-lima-vm ./ubuntu-lts-ebpf.yaml

- go to vm from lima:
limactl shell ebpf-lima-vm
- cd /home/rdawadi.linux/lb-from-scratch

- clone this repo: git clone https://github.com/dwdrajesh/eBPF-rate-limiter.git
- git submodule init
git submodule update

sudo -i
apt install make
apt-get update
apt-get install -y clang llvm libelf-dev libpcap-dev build-essential make
- sudo apt-get install linux-tools-5.15.0-75-generic

- make -> 
make should build and install the load balancer onto the eth0 interface for that container. 
This will compile & install loadbalancer onto the "bpftool net attach xdpgeneric pinned /sys/fs/bpf/xdp_lb dev eth0"


--- Open 4 terminals and :
limactl shell ebpf-lima-vm

sudo -s 
apt  install docker.io -y

---> Dont need this? docker exec -it mynginx /bin/bash
docker run -d --rm --name backend-A -h backend-A --env TERM=xterm-color nginxdemos/hello:plain-text
docker run -d --rm --name backend-B -h backend-B --env TERM=xterm-color nginxdemos/hello:plain-text
docker run --rm -it -h client --name client --env TERM=xterm-color ubuntu

for backend-A container: limactl shell ebpf-lima-vm -> docker exec -it backend-A /bin/bash

--- To check kernel traces on the Lima VM (which is the host, not your MAC for now):
		limactl shell ebpf-lima-vm
		sudo cat /sys/kernel/debug/tracing/trace_pipe

--- Exec into one of the backends and install tcpdump with "apk add tcpdump" if you want to see incoming traffic there.

--- Install ping on client:
apt-get update -y
apt-get install -y iputils-ping



