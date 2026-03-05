
import requests 



def reload_config(ip: str, port: int, config_path: str): 
    files = {'config.ini': open(config_path,'rb')}
    response = requests.post(f'http://{ip}:{port}/reload_config', files=files)
    files['config.ini'].close()
    print(response.json())


if __name__ == "__main__": 
    reload_config("127.0.0.1", 8080, "../control_plane/config.ini")

    





