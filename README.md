## C++ DPI & DLP Packet Sniffer

A high-performance, Dockerized command-line network packet analyzer and Data Leak Prevention (DLP) engine written entirely in C++. Built with libpcap, this tool performs Deep Packet Inspection (DPI) to extract application-layer data (HTTP/HTTPS, DNS, DHCP) and actively monitors outbound traffic for plaintext data leaks.

## Features

* **Deep Packet Inspection (DPI):** Parses unencrypted HTTP hostnames and extracts HTTPS SNI (Server Name Indication) directly from TLS Client Hello packets.

* **Data Leak Prevention (DLP):** Actively monitors outbound HTTP traffic (Port 80) to catch and alert on leaked passwords, session cookies, and POST form data.

* **Smart Interactive UI:** Features a **Targeted Mode** that filters out standard TCP/UDP noise to display only critical application data with ANSI color-coded alerts, alongside a traditional **Verbose Mode**.

* **Protocol Decoding:** Fully decodes Ethernet, IPv4, IPv6, TCP, UDP, ICMP, and ARP headers.

* **Application Layer Analysis:** Extracts human-readable DNS queries and analyzes DHCP (DORA) transactions.

* **Dockerized Architecture:** Runs securely inside an isolated container with host network access. No need to clutter your local machine with C++ libraries.

* **PCAP Dumping:** Automatically saves the captured packet stream to a custom .pcap file on your local host for Wireshark analysis via volume mounting.

## Prerequisites

Since the tool is fully Dockerized, you only need:

* **Docker Engine** installed on your system.

* A Linux/Unix environment (or Windows via a Virtual Machine / WSL2).

* `sudo` privileges to capture network interfaces.

## Installation & Setup

1. **Clone the repository:**
`bash`
`git clone [https://github.com/ArdaEnfalABACI/CPP-Packet-Sniffer.git](https://github.com/ArdaEnfalABACI/CPP-Packet-Sniffer.git)`
`cd CPP-Packet-Sniffer`


2. **Make the run script executable:**
`chmod +x run.sh`


3. **Build the Docker Image:**
This will install build-essential and libpcap-dev inside the container and compile the C++ code.

`sudo docker build -t ardaenfalabaci/cpp-sniffer:v1.0 .`


## Usage
The tool is completely CLI-driven and interactive. Start the engine using the provided shell script, which handles all Docker networking and volume mounts automatically:

`./run.sh`

**Interactive Prompts:**

* Once executed, the interactive wizard will guide you through the setup:

* Output Mode Selection:

* **[V] Verbose Mode:** Displays absolutely all captured packets (Headers, MAC, IP, Ports).

* **[T] Targeted Mode:** Filters out standard ACK/SYN packets and only displays important events like DNS queries, DHCP assignments, SNI targets, and DLP alerts.

* **BPF Filtering:** Enter any standard Berkeley Packet Filter (e.g., tcp port 443, icmp, port 80) or leave blank to capture all traffic.

* **Output File:** Specify a name for the output file (e.g., my_capture.pcap). The file will be saved directly to your current working directory.

## DATA LEAK DETECTED (Outbound Traffic)!
* **Request Line  :** POST /Login.php HTTP/1.1
* **Session Info  :** Cookie: ASPSESSIONID=ABCDEF123456
* **Outbound Data :** username=admin&password=supersecret


## Disclaimer

* This tool was created for educational purposes, network debugging, understanding low-level C++ socket programming, and Machine Learning (ML) dataset generation. Only use it on networks you own or have explicit permission to monitor.
