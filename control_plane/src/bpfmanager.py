import ctypes
import socket
import dnslib
import os
from typing import Callable
from parseutils import domain_to_wire, ip_to_wire


class BPFManager:
    """
    Manage BPF maps and wrap SO functions.

    """

    def __init__(self, so_file: str, ip_map: str, domain_map: str, query_rb: str):
        self.bpf = ctypes.CDLL(so_file)

        self.bpf.get_map_fd.argtypes = [ctypes.c_char_p]

        self._ip_map_fd = self.bpf.get_map_fd(ip_map.encode())
        if self._ip_map_fd < 0:
            raise Exception(f"Failed to find IP map {ip_map}")

        self._domain_map_fd = self.bpf.get_map_fd(domain_map.encode())
        if self._domain_map_fd < 0:
            raise Exception(f"Failed to find domain map {domain_map}")

        self._ringbuffer_fd = self.bpf.get_map_fd(query_rb.encode())
        if self._ringbuffer_fd < 0:
            raise Exception(f"Failed to find ringbuffer {query_rb}")

    def close_maps(self):
        os.close(self._ip_map_fd)
        os.close(self._domain_map_fd)
        os.close(self._ringbuffer_fd)

    def map_ip(self, ip: str):
        if self.bpf.map_ip(self._ip_map_fd, ip_to_wire(ip)) < 0:
            raise Exception(f"Failed to map IP {ip}")

    def unmap_ip(self, ip: str):
        if self.bpf.unmap_ip(self._ip_map_fd, ip_to_wire(ip)) < 0:
            raise Exception(f"Failed to unmap IP {ip}")

    def map_domain(self, domain: str):
        if self.bpf.map_domain(self._domain_map_fd, domain_to_wire(domain)) < 0:
            raise Exception(f"Failed to map domain {domain}")

    def unmap_domain(self, domain: str):
        if self.bpf.unmap_domain(self._domain_map_fd, domain_to_wire(domain)) < 0:
            raise Exception(f"Failed to unmap domain {domain}")

    def set_ringbuffer_callback(
        self, callback: Callable[[str, dnslib.DNSRecord], None]
    ):

        @ctypes.CFUNCTYPE(
            ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t
        )
        def rb_callback(ctx, data, size):

            data = bytearray(ctypes.string_at(data, size))

            ip_address = socket.inet_ntop(socket.AF_INET, data[0:4])
            query = dnslib.DNSRecord.parse(data[4:])

            callback(ip_address, query)

            return 0

        self._saved_callback = rb_callback  # Prevent garbage collection

        if self.bpf.create_ringbuffer(self._ringbuffer_fd, self._saved_callback) < 0:
            raise Exception("Failed to create ring buffer")

    def poll_ringbuffer(self, timeout: int):
        self.bpf.poll_ringbuffer(self._ringbuffer_fd, timeout)
