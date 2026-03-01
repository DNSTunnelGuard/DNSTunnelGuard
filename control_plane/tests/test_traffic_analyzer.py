from trafficanalyzer import TrafficDNSAnalyzer
from recordevent import RecordEvent
from dnslib import DNSRecord, DNSQuestion
import pytest
from datetime import datetime
import dataclasses
import time


@pytest.fixture
def event() -> RecordEvent:
    return RecordEvent(
        src_ip_addr="192.168.55.1",
        timestamp=datetime.now(),
        record=DNSRecord(q=DNSQuestion(qname="attacker.com")),
    )


@pytest.fixture
def analyzer():
    return TrafficDNSAnalyzer(
        weight_percentage=1,
        minute_difference_threshold=5,
        num_queries_threshold=2,
        tld_list=["com"],
        identifer="Traffic"
    )


def test_analyzer_full_suspicious(event: RecordEvent, analyzer: TrafficDNSAnalyzer):
    """
    Test full suspicion percentage on an analyzer that only cares about repeated IP addresses
    """
    sus_level = 0
    for _ in range(2):
        sus_level = analyzer.analyze(event)
    assert sus_level == 1.0


def test_analyzer_half_suspicious(event: RecordEvent, analyzer: TrafficDNSAnalyzer):
    """
    Test half suspicion percentage on an analyzer that only cares about repeated IP addresses
    """
    sus_level = analyzer.analyze(event)
    assert sus_level == 0.5


def test_analyzer_different_domains(event: RecordEvent, analyzer: TrafficDNSAnalyzer):
    """
    Test that an ip querying two different domains does not stack suspicion
    """
    event2 = dataclasses.replace(
        event, record=DNSRecord(q=DNSQuestion(qname="benign.com"))
    )

    assert analyzer.analyze(event) == 0.5
    assert analyzer.analyze(event2) == 0.5


#
def test_reaping(event: RecordEvent):
    """
    Test that old ip domain pairs are removed given a minute difference threshold
    """
    analyzer = TrafficDNSAnalyzer(
        weight_percentage=1,
        minute_difference_threshold=0.001,
        num_queries_threshold=2,
        tld_list=["com"],
        identifer="Traffic"
    )

    # update the timestamp each time an event is analyzed
    first_event = dataclasses.replace(event, timestamp=datetime.now())

    second_event = dataclasses.replace(event, timestamp=datetime.now())

    analyzer.analyze(first_event)

    sus_level = analyzer.analyze(second_event)

    assert sus_level == 1.0

    time.sleep(0.1)

    third_event = dataclasses.replace(event, timestamp=datetime.now())

    new_sus_level = analyzer.analyze(third_event)

    assert new_sus_level == 0.5
