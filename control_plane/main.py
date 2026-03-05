from argparse import ArgumentParser
from configparser import ConfigParser
from guardconfig import GuardConfig, load_guard_controller
from controlserver import ControlServer, ServerEventType, ServerEvent
import sys
import queue 

import logging

logger = logging.getLogger(__name__)


def main():
    parser = ArgumentParser(description="DNS Tunnel Guard Options")

    parser.add_argument("--config_path", required=False, help="Path to config file")

    parser.add_argument(
        "--csv_firewall_path",
        required=False,
        help="Path to emulated CSV file of blocked IP addresses and domain names",
    )

    parser.add_argument(
        "--csv_records_path",
        required=False,
        help="Path to emulated CSV file of DNS records",
    )

    args = parser.parse_args()

    config_path = "config.ini" if args.config_path is None else args.config_path

    config = ConfigParser()
    config.read(config_path)

    logger.info(f"Using configuration {config_path}")

    try:
        guard_config = GuardConfig(config, args)

    except Exception as e:
        logger.critical(f"Invalid configuration: {str(e)}")
        sys.exit(1)

    guard_controller = load_guard_controller(guard_config)

    guard_config.receiver.set_on_recv(guard_controller.process_record)

    logger.info(f"Tunnel Guard Up and Running")

    control_server = ControlServer(config_path, args) 

    server_event_queue = control_server.run()

    try:
        with guard_config.receiver:
            while True: 
                if not guard_config.receiver.receive(1): 
                    break 
                try: 
                    while True: 
                        # handle server events 
                        event = server_event_queue.get_nowait()
                        match event.event_type: 
                            case ServerEventType.CONFIG_RELOAD: 
                                guard_config = event.data 
                                guard_controller = load_guard_controller(guard_config)
                                guard_config.receiver.set_on_recv(guard_controller.process_record)

                except queue.Empty:
                    continue
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
