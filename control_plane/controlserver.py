
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

T = TypeVar('T')

class ServerEventType(Enum): 
    RUNTIME_CONFIG_RELOAD = 1
    TERMINATE = 2

@dataclass 
class ServerEvent(Generic[T]): 
    event_type: ServerEventType
    data: T

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024


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



# --- Server routes operate on control server resources 

@app.route('/reset_runtime_config', methods=['GET'])
def push_config_reset_event(): 
    """
    Reset the config file to the saved config file 

    """
    config = ConfigParser()

    try: 
        config.read(SERVER_RESOURCES.runtime_config.path)

        runtime_config = RuntimeGuardConfig(
            config, 
            SERVER_RESOURCES.config.tld_list, 
            SERVER_RESOURCES.runtime_config.path
        )
    except Exception as e: 
        return jsonify({"Error": f"Invalid configuration: {str(e)}"}), 400

    SERVER_RESOURCES.queue.put(
        ServerEvent(event_type=ServerEventType.RUNTIME_CONFIG_RELOAD, data=runtime_config)
    )

    SERVER_RESOURCES.runtime_config = runtime_config

    return jsonify("Config file reset"), 200


@app.route('/update_runtime_config', methods=['POST'])
def push_config_update_event(): 
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
    do_save_param = request.args.get('save', type=str)
    if not do_save_param: 
        return jsonify({"Error": "Missing save parameter"})

    do_save = True if do_save_param == "true" else False

    config_json = request.get_json()
    if not config_json: 
        return jsonify({"Error": "Missing config updates"}), 400


    config = ConfigParser()
    config.read(SERVER_RESOURCES.runtime_config.path)

    try: 
        for section_key, param in config_json.items(): 
            for key, value in param.items(): 
                config[section_key][key] = value

        runtime_config = RuntimeGuardConfig(
            config, 
            SERVER_RESOURCES.config.tld_list, 
            SERVER_RESOURCES.runtime_config.path
        )
    except Exception as e: 
        return jsonify({"Error": f"Invalid configuration: {str(e)}"}), 400

    if do_save: 
        with open(SERVER_RESOURCES.runtime_config.path, 'w') as f: 
            config.write(f)

    SERVER_RESOURCES.queue.put(
        ServerEvent(event_type=ServerEventType.RUNTIME_CONFIG_RELOAD, data=runtime_config)
    )

    SERVER_RESOURCES.runtime_config = runtime_config

    return jsonify("Config file updated"), 200



@app.route('/reload_runtime_config', methods=['POST'])
def push_config_event():
    """
    Update the runtime config with a new runtime config file.
    Expects a 'true' or 'false' in save query, controlling whether it 
    replaces the runtime config file. 

    Expects a file named 'file' with the config file data 

    """

    do_save_param = request.args.get('save', type=str)
    if not do_save_param: 
        return jsonify({"Error": "Missing save parameter"})

    do_save = True if do_save_param == "true" else False

    file = request.files.get('file')
    if not file: 
        return jsonify({"Error": "Missing file"}), 400

    file_content = file.read()

    if not file_content: 
        return jsonify({"Error": "Could not read file content"}), 400

    config = ConfigParser()
    config.read_string(file_content.decode())

    try: 
        runtime_config = RuntimeGuardConfig(
            config, 
            SERVER_RESOURCES.config.tld_list, 
            SERVER_RESOURCES.runtime_config.path
        )
    except Exception as e: 
        return jsonify({"Error": f"Invalid configuration: {str(e)}"}), 400

    if do_save: 
        with open(SERVER_RESOURCES.runtime_config.path, 'wb') as f: 
            f.write(file_content)

    SERVER_RESOURCES.queue.put(
        ServerEvent(event_type=ServerEventType.RUNTIME_CONFIG_RELOAD, data=runtime_config)
    )

    SERVER_RESOURCES.runtime_config = runtime_config

    return jsonify("Config file uploaded"), 200


@app.route('/terminate', methods=['GET'])
def push_terminate(): 
    """
    Terminate the tunnel guard program

    """
    SERVER_RESOURCES.queue.put(
        ServerEvent(event_type=ServerEventType.TERMINATE, data=None)
    )
    return jsonify("Terminate request sent"), 200




