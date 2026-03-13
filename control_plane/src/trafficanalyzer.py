from dnsanalyzers import DNSAnalyzer
from recordevent import RecordEvent
from datetime import datetime
from collections import defaultdict, deque
import parseutils
import domainlist


class TrafficDNSAnalyzer(DNSAnalyzer):
    """
    Analyze a DNS query based on traffic history

    Uses IP and Domain name pairs to track how often an IP address queries for a
    subdomain. If this IP queries for a subdomain larger a number of times
    large than some threshold, the query is suspicious.

    """

    def __init__(
        self,
        weight_percentage: float,
        identifer: str,
        minute_difference_threshold: float,
        num_queries_threshold: int,
        tld_list: domainlist.DomainList | list[str],
    ):
        """
        weight_percentage:
            Used to store percentage in the analyzer for use of final weight calc
        identifer:
            Name of the analyzer
        minute_difference_threshold:
            The number of minutes a query subdomain pair should be kept in history
        num_queries_threshold:
            The number of times a query subdomain pair needs to be seen for 100% suspicion.
            The suspicion percentage value from analyze will be scaled to this value
        tld_list:
            List of common top level domains, so that some top level domain and ip pairing
            is not counted in history
        """

        super().__init__(weight_percentage, identifer)
        assert num_queries_threshold > 0
        self.history = defaultdict(deque[datetime])
        self.minute_difference_threshold = minute_difference_threshold
        self.num_queries_threshold = num_queries_threshold
        self.tld_list = tld_list

    def analyze(self, dns_event_query: RecordEvent) -> float:
        """
        Analyze a query based on traffic history for the domains and source IP address

        Returns an unweighted suspicion percentage

        """

        ip_address = dns_event_query.src_ip_addr
        domains = []
        for question in dns_event_query.record.questions:
            subdomains = parseutils.split_subdomains(str(question.qname))
            for subdomain in subdomains:
                if subdomain not in self.tld_list:
                    self.history[(ip_address, subdomain)].append(
                        dns_event_query.timestamp
                    )
                    domains.append(subdomain)

        self._reap_old_queries(domains, ip_address)
        self._cleanup_unseen_queries()

        # Return the most sus domain if there were multiple questions
        max_sus_percentage = 0.0
        for domain in domains:
            num_queries = len(self.history[(ip_address, domain)])
            sus_percentage = num_queries / self.num_queries_threshold
            max_sus_percentage = max(sus_percentage, max_sus_percentage)

        return min(1.0, max_sus_percentage)

    def _reap_old_queries(self, domains: list[str], ip_address: str):
        """
        Remove queries greater than the max time difference threshold set in constructor

        """

        now = datetime.now()

        peek_timestamp = lambda key: self.history[key][0] if self.history[key] else None

        for domain in domains:
            timestamp = peek_timestamp((ip_address, domain))
            while (
                timestamp
                and (now - timestamp).total_seconds() / 60
                > self.minute_difference_threshold
            ):
                self.history[(ip_address, domain)].popleft()
                timestamp = peek_timestamp((ip_address, domain))

    def _cleanup_unseen_queries(self): 
        for key in list(self.history): 
            if not self.history[key]: 
                del self.history[key]



    def report(self) -> str:

        report_str = "-- Traffic Analysis Report --\n"
        for key, timestmap in self.history.items():
            addr, domain = key
            report_str += (
                f"IP Address: {addr} | Sub Domain {domain} | Timestamp: {timestmap}"
            )

        return report_str
