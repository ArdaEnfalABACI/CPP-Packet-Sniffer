# C++ Packet Sniffer & PCAP Dumper

A lightweight, high-performance command-line network packet analyzer written entirely in C++. Built with `libpcap`, this tool captures live network traffic, decodes network layer headers, extracts raw payloads, and saves the capture stream into a Wireshark-compatible `.pcap` file for deep analysis.
Fully containerized with Docker for zero-dependency cross-platform execution.

## Features

* **Live Traffic Capture:** Promiscuous mode listening on network interfaces.
* **BPF Filtering:** Full support for Berkeley Packet Filter syntax via command-line arguments.
* **Header Decoding:** Parses and displays MAC addresses, IP addresses, and distinguishes between TCP, UDP, and ICMP protocols.
* **Payload Extraction:** Navigates through Ethernet, IP, and TCP headers using C++ pointer arithmetic to extract and print human-readable ASCII payloads.
* **PCAP Dumping:** Automatically saves the captured packet stream to a custom `.pcap` file for later analysis in Wireshark.
* **Graceful Shutdown:** Catches `SIGINT` (Ctrl+C) to safely close memory handles and prevent `.pcap` file corruption.
* **Dockerized Architecture:** No local compiler or library dependencies required. Runs entirely within an isolated environment.

## Prerequisites

* **Docker** installed and running on your system.
* A Linux environment (or WSL on Windows) to execute the wrapper script.

## Installation

Simply clone the repository and grant execution permissions to the wrapper script:

`bash`

`git clone [https://github.com/ArdaEnfalABACI/CPP-Packet-Sniffer](https://github.com/ArdaEnfalABACI/CPP-Packet-Sniffer)`
`cd CPP-Packet-Sniffer`
`chmod +x run.sh`

## Usage

The tool is completely CLI-driven via the provided run.sh script. This script automatically handles Docker volume mounting and grants the necessary network kernel capabilities to the container.

**Syntax:**

`bash`
`./run.sh [output_file_name] [bpf_filters]`

(Note: The generated .pcap files will be automatically exported to your current working directory from the Docker container).

**Examples:**

1. Capture all traffic and save it to the default `capture.pcap`:

`bash`
`./run.sh`

2. Capture all traffic and save it to a specific file:

`bash`
`./run.sh my_network_test`

3. Capture only secure web traffic (HTTPS) and save it:

`bash`
`./run.sh secure_traffic tcp port 443`

4. Capture only ping requests (ICMP):

`bash`
`./run.sh ping_test icmp`

## Disclaimer
This tool was created for educational purposes, network debugging, and understanding low-level C++ socket programming. Only use it on networks you own or have explicit permission to monitor.
