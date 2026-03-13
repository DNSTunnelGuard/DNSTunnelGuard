from flask import Flask, request, jsonify
from enum import Enum
import threading
from queue import Queue
from typing import TypeVar, Generic
from dataclasses import dataclass
from configparser import ConfigParser
from guardconfig import GuardConfig, RuntimeGuardConfig
from typing import Any

"""
Flask API to control TunnelGuard async

"""

T = TypeVar("T")


class ServerEventType(Enum):
    RUNTIME_CONFIG_RELOAD = 1
    TERMINATE = 2


@dataclass
class ServerEvent(Generic[T]):
    event_type: ServerEventType
    data: T


class ControlServer:
    def __init__(
        self,
        config: GuardConfig,
        runtime_config: RuntimeGuardConfig,
    ):
        self.config = config
        self.runtime_config = runtime_config
        self.queue = Queue()

        self.app = Flask(__name__)
        self.app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024
        self.config_lock = threading.Lock()
        self._register_routes(self.app)

    def run(self) -> Queue[ServerEvent]:
        threading.Thread(
            target=lambda: self.app.run(
                host=self.config.server_host, port=self.config.server_port
            ),
            daemon=True,
        ).start()
        return self.queue

    def _register_routes(self, app: Flask):
        app.add_url_rule(
            "/reset_runtime_config",
            view_func=self._reset_runtime_config,
            methods=["GET"],
        )
        app.add_url_rule(
            "/update_runtime_config",
            view_func=self._update_runtime_config,
            methods=["POST"],
        )
        app.add_url_rule(
            "/reload_runtime_config",
            view_func=self._reload_runtime_config,
            methods=["POST"],
        )
        app.add_url_rule("/terminate", view_func=self._terminate, methods=["GET"])

    def _reload_runtime_config(self):
        """
        Update the runtime config with a new runtime config file.
        Expects a 'true' or 'false' in save query, controlling whether it
        replaces the runtime config file.

        Expects a file named 'file' with the config file data

        """

        do_save_param = request.args.get("save", type=str)
        if not do_save_param:
            return jsonify({"Error": "Missing save parameter"})

        do_save = do_save_param == "true"

        file = request.files.get("file")
        if not file:
            return jsonify({"Error": "Missing file"}), 400

        file_content = file.read()

        if not file_content:
            return jsonify({"Error": "Could not read file content"}), 400

        config = ConfigParser()
        config.read_string(file_content.decode())

        with self.config_lock:
            try:
                runtime_config = RuntimeGuardConfig(
                    config,
                    self.config.tld_list,
                    self.runtime_config.path,
                )
            except Exception as e:
                return jsonify({"Error": f"Invalid configuration: {str(e)}"}), 400

            if do_save:
                with open(self.runtime_config.path, "wb") as f:
                    f.write(file_content)

        self.runtime_config = runtime_config

        self.queue.put(
            ServerEvent(
                event_type=ServerEventType.RUNTIME_CONFIG_RELOAD, data=runtime_config
            )
        )

        return jsonify("Config file uploaded"), 200

    def _update_runtime_config(self):
        """
        Update specific confgiuration values of the runtime config.
        Expects a 'true' or 'false' in save query, controlling whether it
        replaces the runtime config file.

        Expects json to update config options, i.e.
        [analyzer]
        sus_percentage_threshold = 1

        should be

        {
            "analyzer": {
                "sus_percentage_threshold": 1
            }
        }

        """
        do_save_param = request.args.get("save", type=str)
        if not do_save_param:
            return jsonify({"Error": "Missing save parameter"}), 400

        do_save = do_save_param == "true"

        config_json = request.get_json()
        if not config_json:
            return jsonify({"Error": "Missing config updates"}), 400

        config = ConfigParser()
        with self.config_lock:
            config.read(self.runtime_config.path)

            try:
                for section_key, param in config_json.items():
                    for key, value in param.items():
                        config[section_key][key] = value

                runtime_config = RuntimeGuardConfig(
                    config,
                    self.config.tld_list,
                    self.runtime_config.path,
                )
            except Exception as e:
                return jsonify({"Error": f"Invalid configuration: {str(e)}"}), 400

            if do_save:
                with open(self.runtime_config.path, "w") as f:
                    config.write(f)

            self.runtime_config = runtime_config

        self.queue.put(
            ServerEvent(
                event_type=ServerEventType.RUNTIME_CONFIG_RELOAD, data=runtime_config
            )
        )

        return jsonify("Config file updated"), 200

    def _reset_runtime_config(self):
        """
        Reset the config file to the saved config file

        """

        config = ConfigParser()

        with self.config_lock:
            try:
                config.read(self.runtime_config.path)

                runtime_config = RuntimeGuardConfig(
                    config,
                    self.config.tld_list,
                    self.runtime_config.path,
                )
            except Exception as e:
                return jsonify({"Error": f"Invalid configuration: {str(e)}"}), 400

            self.runtime_config = runtime_config

        self.queue.put(
            ServerEvent(
                event_type=ServerEventType.RUNTIME_CONFIG_RELOAD, data=runtime_config
            )
        )

        return jsonify("Config file reset"), 200

    def _terminate(self):
        """
        Terminate the tunnel guard program

        """
        self.queue.put(ServerEvent(event_type=ServerEventType.TERMINATE, data=None))
        return jsonify("Terminate request sent"), 200
