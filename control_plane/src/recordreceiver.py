import queue
import threading
import time
from typing import Callable
from dnslib import DNSRecord, DNSQuestion
import csv
from datetime import datetime
from bpfmanager import BPFManager
from recordevent import RecordEvent


class RecordReceiver:
    """
    Base class of a DNS record receiver. Where the results are received is up to the derived class implementation.
    Creates a receiving thread to not block the receiving queue if computation on the query is expensive

    """

    DEFAULT_MAX_QUEUE_SIZE = 100_000

    def __init__(self, max_queue_size=DEFAULT_MAX_QUEUE_SIZE):
        self._query_queue = queue.Queue(max_queue_size)
        self._recv_thread = None

    def set_on_recv(self, on_recv: Callable[[RecordEvent], None]):
        self._recv_thread = threading.Thread(
            target=self._on_recv_worker, args=(on_recv,)
        )

    def __enter__(self):
        self.start_on_recv_thread()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._query_queue.put(None)
        self.join_on_recv_thread()
        return False

    def receive(self, wait_seconds: int):
        """
        Begin the receive loop to receive records from source
        """
        return self._push_record(wait_seconds)

    # ----------------
    # No need to use these if using "with" context
    def start_on_recv_thread(self):
        if self._recv_thread is None:
            raise Exception("on_recv callback not set")
        self._recv_thread.start()

    def join_on_recv_thread(self):
        if self._recv_thread is None:
            raise Exception("on_recv callback not set")
        self._recv_thread.join()

    # ---------------

    def _on_recv_worker(self, on_recv):
        """
        Runs in a seperate thread, executing the users recv function from records pushed to the query queue

        """
        while True:
            query = self._query_queue.get()
            if query is None:
                break
            on_recv(query)

    def _push_record(self, wait_seconds: int) -> bool:
        """
        Implemented by derived class, pushes record onto the queue from the source
        Returns True if more receiving can be done, False otherwise

        """
        raise NotImplementedError(
            "_receive_record must be implemented by derived classes of RecordReceiver"
        )


class CSVRecordReceiver(RecordReceiver):
    def __init__(
        self,
        path: str,
        max_queue_size=RecordReceiver.DEFAULT_MAX_QUEUE_SIZE,
        cycle_queries=False,
    ):
        self.csv_file = open(path, "r")
        self.csv_reader = csv.reader(self.csv_file)
        self.cycle_queries = cycle_queries
        super().__init__(max_queue_size)

    def __exit__(self, exc_type, exc_value, traceback):
        self.csv_file.close()
        return super().__exit__(exc_type, exc_value, traceback)

    def close(self):
        self.csv_file.close()

    def _push_record(self, wait_seconds: int) -> bool:
        time.sleep(wait_seconds)

        try:
            row = next(self.csv_reader)
        except StopIteration:
            if not self.cycle_queries:
                self._query_queue.put(None)
                return False
            self.csv_file.seek(0)
            return True

        qname, ip_addr = row

        record = DNSRecord(q=DNSQuestion(qname=qname))

        self._query_queue.put(
            RecordEvent(record=record, timestamp=datetime.now(), src_ip_addr=ip_addr)
        )

        return True


class BPFRecordReceiver(RecordReceiver):
    def __init__(
        self,
        bpf_manager: BPFManager,
        max_queue_size=RecordReceiver.DEFAULT_MAX_QUEUE_SIZE,
    ):
        self.bpf_manager = bpf_manager
        self.bpf_manager.set_ringbuffer_callback(
            lambda ip_addr, query: self._query_queue.put(
                RecordEvent(src_ip_addr=ip_addr, record=query, timestamp=datetime.now())
            )
        )
        super().__init__(max_queue_size)

    def _push_record(self, wait_seconds: int) -> bool:
        self.bpf_manager.poll_ringbuffer(wait_seconds)
        return True
