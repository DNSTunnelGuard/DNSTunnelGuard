from recordevent import RecordEvent
from abc import ABC, abstractmethod


class DNSAnalyzer(ABC):
    """
    Abstract Base Class for all types of DNS query analyzers
    """

    def __init__(self, weight_percentage: float, identifer: str):
        self.weight_percentage = weight_percentage
        self.identifer = identifer

    @abstractmethod
    def analyze(self, dns_event_query: RecordEvent) -> float:
        """
        Process and analyze one single DNS query
        Returns weight of suspicion of being tunneling
        """
        ...

    @abstractmethod
    def report(self) -> str:
        """
        Return reported actions and statistics based on analysis
        """
        ...
