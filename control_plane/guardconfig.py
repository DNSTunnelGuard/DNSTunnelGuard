from configparser import ConfigParser
from dnsanalyzers import DNSAnalyzer
from mlanalyzer import MLAnalyzer
from domainlist import DomainList
from firewall import Firewall, BPFFirewall, CSVFirewall
from recordreceiver import RecordReceiver, BPFRecordReceiver, CSVRecordReceiver
from bpfmanager import BPFManager
from dataclasses import dataclass
from trafficanalyzer import TrafficDNSAnalyzer
from entropyanalyzer import EntropyDNSAnalyzer
import logging

logger = logging.getLogger(__name__)


def parse_analyzer_types(
    config: ConfigParser, tld_list: DomainList
) -> list[DNSAnalyzer]:
    analyzers = []

    entropy_config = config["entropyanalyzer"]
    if entropy_config["enabled"] == "true":
        logger.info("Initializing entropy analyzer")
        entropy_config = config["entropyanalyzer"]
        analyzers.append(
            EntropyDNSAnalyzer(
                weight_percentage=float(entropy_config["weight_percentage"]),
                identifer="Entropy",
                max_entropy=float(entropy_config["max_entropy"]),
            )
        )

    traffic_config = config["trafficanalyzer"]
    if traffic_config["enabled"] == "true":
        logger.info("Initializing traffic analyzer")
        analyzers.append(
            TrafficDNSAnalyzer(
                weight_percentage=float(traffic_config["weight_percentage"]),
                identifer="Traffic",
                minute_difference_threshold=float(
                    traffic_config["minute_difference_threshold"]
                ),
                num_queries_threshold=int(traffic_config["num_queries_threshold"]),
                tld_list=tld_list,
            )
        )

    mlanalyzer_config = config["mlanalyzer"]
    if mlanalyzer_config["enabled"] == "true":
        logger.info("Initializing ML analyzer")
        analyzers.append(
            MLAnalyzer(
                weight_percentage=float(mlanalyzer_config["weight_percentage"]),
                identifer="ML",
                apiurl=mlanalyzer_config["apiurl"]
            )
        )

    return analyzers


def parse_dns_whitelist_types(config: ConfigParser) -> list[DomainList]:

    dns_lists = []

    top_domains_config = config["top_domains_list"]
    if top_domains_config["enabled"] == "true":
        logger.info("Initializing DNS Whitelists")
        dns_lists.append(DomainList(path=top_domains_config["path"]))

    return dns_lists


def parse_tld_list(config: ConfigParser) -> DomainList:
    top_tld_config = config["top_tld_list"]
    logger.info("Initializing TLD List")
    return DomainList(path=top_tld_config["path"])


# ------------- Guard Controller Resources


def parse_guard_types(args, config: ConfigParser) -> tuple[RecordReceiver, Firewall]:

    resources = GuardResources(
        bpf_manager=None, firewall_csv_path=None, receiver_csv_path=None
    )

    resources.firewall_csv_path = args.csv_firewall_path

    resources.receiver_csv_path = args.csv_records_path

    return parse_record_receiver(config, resources), parse_firewall(config, resources)


@dataclass
class GuardResources:
    bpf_manager: BPFManager | None
    firewall_csv_path: str | None
    receiver_csv_path: str | None


def parse_ebpf_config(config: ConfigParser) -> BPFManager:
    ebpf_config = config["ebpf"]
    return BPFManager(
        so_file=ebpf_config["so_file"],
        ip_map=ebpf_config["ip_map"],
        domain_map=ebpf_config["domain_map"],
        query_rb=ebpf_config["query_rb"],
    )


def parse_firewall(config: ConfigParser, resources: GuardResources) -> Firewall:
    firewall_type = config["firewall"]["type"]
    if firewall_type == "ebpf":
        if resources.bpf_manager is None:
            resources.bpf_manager = parse_ebpf_config(config)
        return BPFFirewall(resources.bpf_manager)
    elif firewall_type == "csv":
        if resources.firewall_csv_path is None:
            resources.firewall_csv_path = "blocked.csv"
        return CSVFirewall(resources.firewall_csv_path)
    else:
        raise Exception(f"Invalid firewall type {firewall_type}")


def parse_record_receiver(
    config: ConfigParser, resources: GuardResources
) -> RecordReceiver:
    receiver_type = config["recordreceiver"]["type"]
    if receiver_type == "ebpf":
        if resources.bpf_manager is None:
            resources.bpf_manager = parse_ebpf_config(config)
        return BPFRecordReceiver(resources.bpf_manager)

    elif receiver_type == "csv":
        if resources.receiver_csv_path is None:
            raise Exception("Path to CSV DNS Records not provided")
        return CSVRecordReceiver(resources.receiver_csv_path)
    else:
        raise Exception(f"Invalid Record Receiver type: {receiver_type}")


# ---------------- Logging


def setup_logging(config: ConfigParser):

    level_str = config["logging"]["level"]
    level = logging.DEBUG

    match level_str:
        case "DEBUG":
            level = logging.DEBUG
        case "INFO":
            level = logging.INFO
        case "WARNING":
            level = logging.WARNING
        case "ERROR":
            level = logging.ERROR
        case "CRITICAL":
            level = logging.CRITICAL
        case _:
            raise Exception("Invalid logging level")

    output = config["logging"]["output"]

    if output != "stdout":
        logging.basicConfig(filename=output, level=level)
    else:
        logging.basicConfig(level=level)


def parse_blacklist(config: ConfigParser) -> DomainList:
    return DomainList(config["domain_blacklist"]["path"])


def parse_percentage_threshold(config: ConfigParser) -> float:
    return float(config["analyzer"]["sus_percentage_threshold"])
