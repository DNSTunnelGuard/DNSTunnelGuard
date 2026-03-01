from dnsanalyzers import DNSAnalyzer
from recordevent import RecordEvent
from parseutils import parse_qname
import requests



class MLAnalyzer(DNSAnalyzer): 
    """
    Send a GET request to the ML model calculating the weight percentage 

    """
    
    def __init__(self, weight_percentage: float, identifer: str, apiurl: str): 
        """
        apiurl: 
            Url to the ML response, expecting /weight with query value being the qname.
            returns a json response 'weight_percentage': float

        """

        super().__init__(weight_percentage, identifer)
        self.apiurl = apiurl
        self.req_error_code = None
        self.request_responses = []

    def analyze(self, dns_event_query: RecordEvent) -> float: 

        max_weight = 0
        for q in dns_event_query.record.questions: 

            parsed_qname = parse_qname(str(q.qname))

            response = requests.get(f"{self.apiurl}/weight", params={"query": parsed_qname})
            if response.status_code != 200:
                self.req_error_code = response.status_code
                return 0
            else: 
                self.req_error_code = None
            result = response.json()
            self.request_responses.append(result)
            weight = float(result.get("weight_percentage", 0.0))
            max_weight = max(max_weight, weight)

        return max_weight

    def report(self) -> str: 
        if self.req_error_code is not None: 
            return f"ML Analayzer returned a {self.req_error_code} response"
        
        return f"ML Request responses: {self.request_responses}"
