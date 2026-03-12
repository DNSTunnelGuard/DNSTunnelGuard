from recordevent import RecordEvent


class DNSAnalyzer:
    """
    Abstract Base Class for all types of DNS query analyzers
    """

    def __init__(self, weight_percentage: float, identifer: str):
        self.weight_percentage = weight_percentage
        self.identifer = identifer

    def analyze(self, dns_event_query: RecordEvent) -> float:
        """
        Process and analyze one single DNS query
        Returns weight of suspicion of being tunneling
        """
        raise NotImplementedError("process event method not implemented")

    def report(self) -> str:
        """
        Return reported actions and statistics based on analysis
        """
        raise NotImplementedError("report method not implemented")
