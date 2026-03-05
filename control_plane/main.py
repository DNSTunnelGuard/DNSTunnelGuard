from argparse import ArgumentParser
from configparser import ConfigParser
from guardcontroller import GuardController
from guardconfig import GuardConfig
import sys

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

    guard_controller = GuardController(
        whitelists=guard_config.whitelists,
        analyzers=guard_config.analyzers,
        firewall=guard_config.firewall,
        blacklist=guard_config.blacklist,
        sus_percentage_threshold=guard_config.percentage_threshold,
        tld_list=guard_config.tld_list,
    )

    guard_config.receiver.set_on_recv(guard_controller.process_record)

    logger.info(f"Tunnel Guard Up and Running")

    try:
        with guard_config.receiver:
            guard_config.receiver.receive()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
