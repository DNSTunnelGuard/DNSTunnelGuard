from dnslib import DNSRecord
from dataclasses import dataclass
from datetime import datetime


@dataclass
class RecordEvent:
    """
    Event for either query or response receival
    """

    record: DNSRecord
    timestamp: datetime
    src_ip_addr: str
