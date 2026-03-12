import struct
import socket


def split_subdomains(qname: str) -> list[str]:
    """
    Splits a qname into subdomains
    Ex: jjj.attacker.com -> ['jjj.attacker.com', 'attacker.com', '.com']
    """
    if not qname:
        return []

    domains = qname.split(".")

    split = [".".join(domains[i:]) for i in range(len(domains)) if domains[i]]

    for i in range(len(split)):
        if split[i][-1] == ".":
            split[i] = split[i][:-1]

    return split


def parse_qname(qname: str) -> str:
    if qname.endswith("."):
        return qname[:-1]
    return qname


def tld(qname: str) -> str:
    """
    Get the top level domain of a full domain name
    """
    domains = qname.split(".")

    if len(domains) <= 1:
        return qname

    if domains[-1]:
        return domains[-1]
    else:
        return domains[-2]


def ip_to_wire(ip_addr: str):
    ip_bytes = socket.inet_pton(socket.AF_INET, ip_addr)
    return struct.unpack("I", ip_bytes)[0]


def domain_to_wire(domain: str) -> bytes:
    domains = domain.split(".")

    wire_domain = b""

    for d in domains:
        wire_domain += len(d).to_bytes(1)
        wire_domain += d.encode("utf-8")

    wire_domain += b"\x00"
    return wire_domain
