


# DNS Tunnel Guard Control Plane  

## Overview

**DNS Tunnel Guard Control Plane** is responsible for analyzing queries and updating shared eBPF maps of blocked IP addresses and domain names. 

---

## Detection Methodologies

- **Entropy Analysis**  
  Evaluates the randomness (entropy) of DNS queries to spot anomalous, tunnel-like payloads.

- **Traffic Analysis**  
  Monitors frequency and patterns of requests to specific subdomains and tracks activity from individual source IP addresses.

- **Machine Learning (ML) Analysis**  
  Employs a BERT-based model trained on both suspicious and benign DNS queries to intelligently flag potential tunneling attempts.

---


## Configuration 

- View **config/config.ini** for configuring startup parameters (i.e. eBPF mode or emulated CSV mode)
- View **config/runtime_config.ini**  for configuring runtime parameters that can be updated during the execution of the program via the control server 

## Control Server 
The control server is a REST API used to interact with the program during it's execution. See controlserverAPI.md for details 

## Get Started

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh # install uv package manager if neccessary 

uv sync 

source .venv/bin/activate 

python3 src/main.py -h  # view args needed to run 

```

To run outside of emulated CSV mode, eBPF support and GCC are required. 
``` bash
bash ./scripts/compile_libguard.sh
```

