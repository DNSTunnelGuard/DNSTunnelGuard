from bpfmanager import BPFManager


class Firewall:
    def block_domain(self, domain: str):
        raise NotImplementedError("block_domain not implemented")

    def block_ip_address(self, ip_address: str):
        raise NotImplementedError("block_ip_address not implemented")


class CSVFirewall(Firewall):
    def __init__(self, path: str):
        self._path = path
        self._csv_file = open(self._path, "a")

    def block_domain(self, domain: str):
        self._csv_file.write(f"{domain},\n")

    def block_ip_address(self, ip_address: str):
        self._csv_file.write(f",{ip_address}\n")


class BPFFirewall(Firewall):
    def __init__(self, bpf_manager: BPFManager):
        self.bpf_manager = bpf_manager

    def block_ip_address(self, ip_address: str):
        self.bpf_manager.map_ip(ip_address)

    def unblock_ip_address(self, ip_address: str):
        self.bpf_manager.unmap_ip(ip_address)

    def block_domain(self, domain: str):
        self.bpf_manager.map_domain(domain)

    def unblock_domain(self, domain: str):
        self.bpf_manager.unmap_domain(domain)
