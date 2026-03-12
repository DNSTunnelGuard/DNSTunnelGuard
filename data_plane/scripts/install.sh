
apk add clang 

apk add gcc

apk add unbound

rc-update add cgroups boot

rc-service cgroups start

grep -qxF 'rc_cgroup_mode="unified"' /etc/conf.d/unbound || echo 'rc_cgroup_mode="unified"' >> /etc/conf.d/unbound

rc-service unbound restart

apk add clang llvm bpftool libbpf-dev make linux-lts-dev

mkdir -p /sys/fs/bpf/

gcc -fPIC -shared -o /root/control_plane/libguard.so /root/control_plane/bpf/libguard.c -lbpf

bpftool btf dump file /sys/kernel/btf/vmlinux format c > /root/data_plane/vmlinux.h

sh /root/scripts/update_guards.sh

