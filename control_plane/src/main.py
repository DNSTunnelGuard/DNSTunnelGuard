from argparse import ArgumentParser
import guardconfig
from controlserver import ControlServer, ServerEventType
from guardcontroller import GuardController
from recordreceiver import RecordReceiver
import sys
import queue

import logging

logger = logging.getLogger(__name__)


def run_event_loop(
    receiver: RecordReceiver,
    guard_controller: GuardController,
    server_event_queue: queue.Queue,
):
    with receiver:
        while True:
            try:
                while True:
                    # handle server events
                    event = server_event_queue.get_nowait()
                    match event.event_type:
                        case ServerEventType.RUNTIME_CONFIG_RELOAD:
                            runtime_config = event.data
                            guardconfig.update_guard_controller(
                                guard_controller, runtime_config
                            )
                            logger.info("Runtime config reloaded")
                        case ServerEventType.TERMINATE:
                            logger.info("Terminating")
                            return

            except queue.Empty:
                pass

            if not receiver.receive(1):
                break


def main():
    parser = ArgumentParser(description="DNS Tunnel Guard Options")

    parser.add_argument(
        "-c",
        "--config_path",
        required=False,
        help="Path to config file",
        default="config/config.ini",
    )

    parser.add_argument(
        "-rc",
        "--runtime_config_path",
        required=False,
        help="Path to runtime config file",
        default="config/runtime_config.ini",
    )

    parser.add_argument(
        "-f",
        "--csv_firewall_path",
        required=False,
        help="Path to emulated CSV file of blocked IP addresses and domain names",
    )

    parser.add_argument(
        "-r",
        "--csv_records_path",
        required=False,
        help="Path to emulated CSV file of DNS records",
    )

    parser.add_argument(
        "-y",
        "--cycle_csv_queries",
        required=False,
        help="Cycle CSV record queries",
        action="store_true",
    )

    args = parser.parse_args()

    logger.info(
        f"Using configuration {args.config_path} and runtime configuration {args.runtime_config_path}"
    )

    try:
        config, runtime_config = guardconfig.get_configs(args)

    except Exception as e:
        logger.critical(f"Invalid configuration: {str(e)}")
        sys.exit(1)

    guard_controller = guardconfig.load_guard_controller(config, runtime_config)

    config.receiver.set_on_recv(guard_controller.process_record)

    logger.info(f"Tunnel Guard Up and Running\n\n")

    control_server = ControlServer(config, runtime_config)

    server_event_queue = control_server.run()

    try:
        run_event_loop(config.receiver, guard_controller, server_event_queue)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
