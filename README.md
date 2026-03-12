# DNS Tunnel Guard

## Overview

**DNS Tunnel Guard** is a modern DNS tunneling detection and mitigation system designed to integrate seamlessly with any Linux DNS resolver.  
It monitors both inbound and outbound DNS traffic, applies multiple detection methodologies, and proactively blocks malicious domains and source IP addresses when tunneling activity is suspected.

---

## Features

- **Attach to any Linux DNS resolver with cgroup eBPF support**
- **Real-time traffic inspection**
- **Multiple detection methodologies**
- **Automated mitigation (blocking domains and IPs)**

---

## Detection Methodologies

- **Entropy Analysis**  
  Evaluates the randomness (entropy) of DNS queries to spot anomalous, tunnel-like payloads.

- **Traffic Analysis**  
  Monitors frequency and patterns of requests to specific subdomains and tracks activity from individual source IP addresses.

- **Machine Learning (ML) Analysis**  
  Employs a BERT-based model trained on both suspicious and benign DNS queries to intelligently flag potential tunneling attempts.

---

## Get Started
The program consists of the control plane, the data plane, and BERT analyzer REST API. The control plane and BERT API can be ran on any system, while the data plane 
requires Linux cgroup eBPF support. 

Currently, the only installation script available is for Alpine Linux using the Unbound resolver. DNS tunnel guard control plane can be ran in an emulated CSV mode
for testing if the data plane is not active. 

To run the control plane, 
```bash
cd control_plane
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 main.py -h # Display options to run the program. 
```
Configurations can be made in config.ini and runtime_config.ini.

To run the BERT API, 
```bash
cd bert
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 main.py -h # Display options to run the program. 
```
[TODO]


