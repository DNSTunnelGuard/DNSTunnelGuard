# DNS Tunnel Guard

## Overview

**DNS Tunnel Guard** is a modern DNS tunneling detection and mitigation system designed to integrate seamlessly with any Linux DNS resolver.  
It monitors both inbound and outbound DNS traffic, applies multiple advanced detection methodologies, and proactively blocks malicious domains and source IP addresses when tunneling activity is suspected.

---

## Features

- **Attach to any Linux DNS resolver**
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

1. **Install & configure** DNS Tunnel Guard alongside your resolver.
2. **Monitor** your DNS traffic with built-in analytics.
3. **Mitigate** threats automatically with minimal manual intervention.

---

*Secure your DNS infrastructure. Detect and defeat DNS tunneling with precision.*


