

bpftool cgroup detach /sys/fs/cgroup/openrc.unbound ingress pinned /sys/fs/bpf/ingress_guard
bpftool cgroup detach /sys/fs/cgroup/openrc.unbound egress pinned /sys/fs/bpf/egress_guard

rm -f /sys/fs/bpf/ingress_guard
rm -f /sys/fs/bpf/egress_guard

