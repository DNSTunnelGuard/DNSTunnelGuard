
import requests 
from typing import Any


def reload_config(ip: str, port: int, config_path: str, save=False) -> requests.Response: 
    with open(config_path, 'rb') as f: 
        files = {'file': (config_path, f, 'text/plain')}
        response = requests.post(
            f'http://{ip}:{port}/reload_runtime_config', 
            files=files, 
            params={"save": "true" if save else "false"}
        )
    return response


def update_config(ip: str, port: int, values: dict[str, Any], save=False) -> requests.Response: 
    return requests.post(
        f'http://{ip}:{port}/update_runtime_config', 
        params={"save": "true" if save else "false"},
        json=values
    )

def terminate(ip: str, port: int) -> requests.Response: 
    return requests.get(
        f'http://{ip}:{port}/terminate', 
    )


if __name__ == "__main__": 
    print("TunnelGuard Client")
    print("Enter T to terminate")
    while True: 
        i = input().upper()
        match i: 
            case 'T': 
                try: 
                    response = terminate("127.0.0.1", 8080)
                    if response.status_code == 200: 
                        print("Successfully terminated")
                        break 
                    else: 
                        print("Error:", response.json()["error"])
                except: 
                    print("Could not connect to TunnelGuard server")








