from dnsanalyzers import DNSAnalyzer
from domainlist import DomainList
from recordevent import RecordEvent
from firewall import Firewall
import parseutils

import logging

logger = logging.getLogger(__name__)


class GuardController:
    """
    Manages analyzers and firewall to dispatch the different analyizers and block the IP and domain
    if these analyzers find the query suspicious

    """

    def __init__(
        self,
        whitelists: list[DomainList],
        analyzers: list[DNSAnalyzer],
        firewall: Firewall,
        blacklist: DomainList | None,
        sus_percentage_threshold: float,
        tld_list: DomainList | None = None,
    ):
        """
        whitelists:
            list of domainlists that hold trusted domains
        analyzers:
            List of analyzers to analyze each query
        firewall:
            firewall used to block IP's and domains
        blacklist:
            dnslist of untrusted domains
        sus_percentage_threshold:
            Percentage that if a query exceeds this sus threshold, the srouce IP address and domain queried
            for are blocked
        tld_checker:
            CSV checker that can tell if a sub domain is a TLD

        """
        self.whitelists = whitelists
        self.analyzers = analyzers
        self.firewall = firewall
        self.sus_percentage_threshold = sus_percentage_threshold
        self.tld_list = tld_list
        self.blacklist = blacklist

        if blacklist is not None:
            for domain in blacklist:
                self.firewall.block_domain(domain)

    def process_record(self, event: RecordEvent):
        """
        Callback to be used on every record event
        """
        logger.debug(event)
        qnames = [
            parseutils.parse_qname(str(question.qname))
            for question in event.record.questions
        ]

        logger.info(
            f"Query Received. Domains: {qnames} from IP address {event.src_ip_addr} at {event.timestamp}"
        )

        if all(any(domain in wl for wl in self.whitelists) for domain in qnames):
            logger.info("Queries found benign")
            return

        blockable_domains = []
        for qname in qnames:
            blockable_domains.extend(self._get_blockable_domains(qname))
        sus_percentage = 0.0

        for analyzer in self.analyzers:
            analyzer_percentage = analyzer.analyze(event) * analyzer.weight_percentage
            sus_percentage += analyzer_percentage
            logger.debug(analyzer.report())
            logger.info(
                f"{analyzer.identifer} analyzer found query {analyzer_percentage * 100}% suspicious"
            )

        logger.info(f"Total query suspicion percentage: {sus_percentage * 100}%")
        if sus_percentage >= self.sus_percentage_threshold:
            logger.warning(
                f"Suspicious query detected from IP address {event.src_ip_addr}"
            )
            logger.warning(f"Blocking IP address {event.src_ip_addr}")

            self.firewall.block_ip_address(event.src_ip_addr)
            for domain in blockable_domains:
                logger.warning(f"Blocking suspicious domain {domain}")
                self.firewall.block_domain(domain)
                if self.blacklist is not None:
                    self.blacklist.update(domain)

    def _get_blockable_domains(self, qname: str) -> list[str]:
        sub_domains = parseutils.split_subdomains(qname)
        return [
            domain
            for domain in sub_domains
            if self.tld_list is None or not domain in self.tld_list
        ]
