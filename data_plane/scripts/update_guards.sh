
bpftool cgroup detach /sys/fs/cgroup/openrc.unbound ingress pinned /sys/fs/bpf/ingress_guard
bpftool cgroup detach /sys/fs/cgroup/openrc.unbound egress pinned /sys/fs/bpf/egress_guard

rm -f /sys/fs/bpf/ingress_guard
rm -f /sys/fs/bpf/egress_guard

clang -O2 -g -target bpf -c /root/data_plane/ingress_guard.c -o /root/data_plane/ingress_guard.o
clang -O2 -g -target bpf -c /root/data_plane/egress_guard.c -o /root/data_plane/egress_guard.o

bpftool prog load /root/data_plane/ingress_guard.o /sys/fs/bpf/ingress_guard  
bpftool prog load /root/data_plane/egress_guard.o /sys/fs/bpf/egress_guard 

bpftool cgroup attach /sys/fs/cgroup/openrc.unbound ingress pinned /sys/fs/bpf/ingress_guard
bpftool cgroup attach /sys/fs/cgroup/openrc.unbound egress pinned /sys/fs/bpf/egress_guard
