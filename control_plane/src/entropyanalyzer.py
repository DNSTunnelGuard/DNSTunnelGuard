from dnsanalyzers import DNSAnalyzer
from recordevent import RecordEvent
import math
from collections import Counter


class EntropyDNSAnalyzer(DNSAnalyzer):
    """
    DNSAnalyzer child class that analyzes DNS query qnames for different levels of entropy (randomness)
    """

    def __init__(
        self, weight_percentage: float, identifer: str, max_entropy: float
    ) -> None:
        super().__init__(weight_percentage, identifer)
        self.max_entropy = max_entropy

    def analyze(self, dns_event_query: RecordEvent) -> float:
        # Entropy Analysis
        qname: str = str(dns_event_query.record.questions[0].qname)

        # DNS tunneling most often puts payload data in the left most label. Hence, we will analyze only the left most label.
        left_label = self._get_leftmost_label(qname)

        # Use Shannon entropy analysis to measure the randomness of the symbol distribution.
        entropy = self._shannon_entropy(left_label)

        if entropy >= self.max_entropy:
            return 1.0
        else:
            return round((entropy / self.max_entropy), 2)

    def _get_leftmost_label(self, qname: str) -> str:
        return qname.split(".")[0].lower()

    def _shannon_entropy(self, left_label: str) -> float:
        if not left_label:
            return 0.0

        counts = Counter(left_label)
        length = len(left_label)

        entropy_val = 0.0
        for count in counts.values():
            p = count / length
            entropy_val -= p * math.log2(p)

        return round(entropy_val, 2)

    def report(self) -> str:
        return ""
