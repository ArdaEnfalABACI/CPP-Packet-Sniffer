# C++ Packet Sniffer & PCAP Dumper

A lightweight, high-performance command-line network packet analyzer written entirely in C++. Built with `libpcap`, this tool captures live network traffic, decodes network layer headers, extracts raw payloads, and saves the capture stream into a Wireshark-compatible `.pcap` file for deep analysis.

## 🚀 Features

* **Live Traffic Capture:** Promiscuous mode listening on network interfaces.
* **BPF Filtering:** Full support for Berkeley Packet Filter syntax via command-line arguments (e.g., `tcp port 80`, `icmp`).
* **Header Decoding:** Parses and displays MAC addresses, IP addresses, and distinguishes between TCP, UDP, and ICMP protocols.
* **Payload Extraction:** Navigates through Ethernet, IP, and TCP headers using C++ pointer arithmetic to extract and print human-readable ASCII payloads.
* **PCAP Dumping:** Automatically saves the captured packet stream to a custom `.pcap` file for later analysis in Wireshark.
* **Graceful Shutdown:** Catches `SIGINT` (Ctrl+C) to safely close memory handles and prevent `.pcap` file corruption.

## 🛠️ Prerequisites

This tool is built for Linux/Unix environments. You need the `libpcap` development library installed on your system.

For Debian/Ubuntu-based systems:

`bash`
`sudo apt update`

`bash`
`sudo apt install build-essential libpcap-dev`


## ⚙️ Compilation

Clone the repository and compile the source code using `g++`:

`bash`
`git clone https://github.com/ArdaEnfalABACI/cpp-packet-sniffer.git`

`bash`
`cd cpp-packet-sniffer`

`bash`
`g++ web_sniffer.cpp -o web_sniffer -lpcap`

*(Note: Do not forget to link the pcap library using the `-lpcap` flag).*

## 📖 Usage

The tool is completely CLI-driven. You can specify the output file name and apply BPF filters directly from the terminal.

**Syntax:**
`bash`
`sudo ./web_sniffer [output_file_name] [bpf_filters...]`


**Examples:**

1. Capture all traffic and save it to the default `capture.pcap`:
`bash`
`sudo ./web_sniffer`

2. Capture all traffic and save it to a specific file:
`bash`
`sudo ./web_sniffer my_network_test`

3. Capture only secure web traffic (HTTPS) and save it:
`bash`
`sudo ./web_sniffer secure_traffic tcp port 443`

4. Capture only ping requests (ICMP):
`bash`
`sudo ./web_sniffer ping_test icmp`

## ⚠️ Disclaimer
This tool was created for educational purposes, network debugging, and understanding low-level C++ socket programming. Only use it on networks you own or have explicit permission to monitor.
