
from flask import Flask, request, jsonify
from enum import Enum 
import threading 
from queue import Queue
from typing import TypeVar, Generic
from dataclasses import dataclass 
from configparser import ConfigParser
from guardconfig import GuardConfig

T = TypeVar('T')

class ServerEventType(Enum): 
    CONFIG_RELOAD = 1

@dataclass 
class ServerEvent(Generic[T]): 
    event_type: ServerEventType
    data: T

class ControlServer: 
    
    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024
    allowed_extensions = { 'ini' }

    def __init__(self, config_path: str, args, host="0.0.0.0", port=8080): 
        self.args = args
        self.config_path = config_path
        self.host = host 
        self.port = port
        self.queue = Queue()

    def run(self) -> Queue[ServerEvent]: 
        threading.Thread(target=lambda: self.app.run(host=self.host, port=self.port), daemon=True).start()
        return self.queue 


    @app.route('/reload_config', methods=['POST'])
    def _push_config_event(self):
        file = request.files.get('file')
        if not file: 
            return jsonify("Missing file"), 400

        file_content = file.read()

        if not file_content: 
            return jsonify("Could not read file content"), 400

        config = ConfigParser()
        config.read(file_content)

        try: 
            guard_config = GuardConfig(config, self.args)
        except Exception as e: 
            return jsonify(f"Invalid configuration: {str(e)}"), 500

        with open(self.config_path, 'w') as f: 
            f.write(file_content)

        self.queue.put(ServerEvent(event_type=ServerEventType.CONFIG_RELOAD, data=guard_config))

        return jsonify("Config file uploaded"), 200

            


