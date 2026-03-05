
from flask import Flask, request, jsonify
from enum import Enum 
import threading 
from queue import Queue
from typing import TypeVar, Generic
from dataclasses import dataclass 
from configparser import ConfigParser
from guardconfig import GuardConfig, RuntimeGuardConfig
from typing import Any
from collections import namedtuple

T = TypeVar('T')

class ServerEventType(Enum): 
    RUNTIME_CONFIG_RELOAD = 1
    PRINT_STATUS = 2

@dataclass 
class ServerEvent(Generic[T]): 
    event_type: ServerEventType
    data: T

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024
allowed_extensions = { 'ini' }


@dataclass
class ServerResources: 
    host: Any = None
    port: Any = None
    queue: Any = None
    config: Any = None
    runtime_config: Any = None

SERVER_RESOURCES = ServerResources()

def run_server(
        config: GuardConfig, 
        runtime_config: RuntimeGuardConfig, 
    ) -> Queue[ServerEvent]: 

    global SERVER_RESOURCES
    SERVER_RESOURCES = ServerResources(
        host=config.server_host,
        port=config.server_port,
        queue=Queue(),
        config=config,
        runtime_config=runtime_config
    )

    threading.Thread(
        target=lambda: 
            app.run(host=SERVER_RESOURCES.host, port=SERVER_RESOURCES.port), daemon=True).start()
    return SERVER_RESOURCES.queue 

    return Queue()


# --- Server routes operate on control server resources 

@app.route('/reload_runtime_config', methods=['POST'])
def push_config_event():
    file = request.files.get('file')
    if not file: 
        return jsonify("Missing file"), 400

    file_content = file.read()

    if not file_content: 
        return jsonify("Could not read file content"), 400

    config = ConfigParser()
    config.read_string(file_content.decode())

    try: 
        runtime_config = RuntimeGuardConfig(
            config, 
            SERVER_RESOURCES.config.tld_list, 
            SERVER_RESOURCES.runtime_config.path
        )
    except Exception as e: 
        return jsonify(f"Invalid configuration: {str(e)}"), 500

    with open(SERVER_RESOURCES.runtime_config.path, 'wb') as f: 
        f.write(file_content)

    SERVER_RESOURCES.queue.put(
        ServerEvent(event_type=ServerEventType.RUNTIME_CONFIG_RELOAD, data=runtime_config)
    )

    SERVER_RESOURCES.runtime_config = runtime_config

    return jsonify("Config file uploaded"), 200

        


