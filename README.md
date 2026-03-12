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

The project consists of three modules: the control plane, data plane, and BERT API. A corresponding README.md is in each directory 
for instructions on how to run. 

The data plane is only necessary if running outside of the emulated CSV mode. The BERT REST API server is only necessary if using the ML analyzer 
