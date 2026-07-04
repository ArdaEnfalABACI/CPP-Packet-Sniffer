#include <iostream>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>   
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <cctype>
#include <csignal>
#include <string>
#include <sstream> 

using namespace std;

// Global variables
pcap_t *global_handle = nullptr; 
bool verbose_mode = true; 

// --- ANSI COLOR CODES (For better terminal UI) ---
const string COLOR_RESET = "\033[0m";
const string COLOR_GREEN = "\033[1;32m";
const string COLOR_RED   = "\033[1;31m";
const string COLOR_CYAN  = "\033[1;36m";
const string COLOR_YELLOW= "\033[1;33m";

// --- DHCP HEADER STRUCTURE ---
// We create our own template to read DHCP packets easily
struct dhcp_header {
    uint8_t op;            // OpCode: 1 = Request, 2 = Reply
    uint8_t htype;         // Hardware Type
    uint8_t hlen;          // Hardware Address Length
    uint8_t hops;          // Relay hops
    uint32_t xid;          // Transaction ID (Matches request with reply)
    uint16_t secs;         // Seconds elapsed
    uint16_t flags;        // Broadcast flags
    struct in_addr ciaddr; // Client IP 
    struct in_addr yiaddr; // "Your" IP (Given by server)
    struct in_addr siaddr; // Server IP
    struct in_addr giaddr; // Gateway IP
    u_char chaddr[16];     // Client MAC Address
};

// --- GRACEFUL SHUTDOWN HANDLER ---
// Triggers when you press Ctrl+C
void signal_handler(int signum) {
    cout << endl << COLOR_RED << "[!] Shutdown signal received! Closing gracefully..." << COLOR_RESET << endl;
    if (global_handle != nullptr) {
        pcap_breakloop(global_handle);
    }
}

// --- DNS NAME PARSER ---
// Converts network DNS format (e.g., 3www6google3com0) to standard string (www.google.com)
string parse_dns_name(const u_char* payload, int& offset, int max_len){
    string name = "";
    int i = offset;

    while (i < max_len && payload[i] != 0) {
        int len = payload[i];

        // Security check for DNS Compression Pointer (Starts with 0xC0)
        if ((len & 0xC0) == 0xC0){
            name += "<compressed>";
            i += 2;
            offset = i;
            return name;
        }
        i++;
        // Read characters
        for (int j = 0; j < len && i < max_len; j++ , i++){
            name += payload[i];
        }
        name += "."; // Add dot between words
    }
    // Remove the last extra dot
    if (name.length() > 0) name.pop_back();
    offset = i + 1;
    return name;
}

// --- HTTP HOST PARSER ---
// Finds the "Host: www.site.com" text inside unencrypted HTTP packets
string parse_http_host(const u_char* payload, int payload_length) {
    string data(reinterpret_cast<const char*>(payload), payload_length);
    size_t host_pos = data.find("Host: ");

    if (host_pos != string::npos) {
        size_t end_pos = data.find("\r\n", host_pos);
        if (end_pos != string::npos) {
            // "Host: " is 6 characters long. We skip it to get only the domain name.
            return data.substr(host_pos + 6, end_pos - (host_pos + 6));
        }
    }
    return "";
}

// OUTBOUND HTTP DATA PARSER 
// Catches data leaving our machine (GET parameters, POST forms, Cookies)
string parse_outbound_http(const u_char* payload, int payload_length) {
    string data(reinterpret_cast<const char*>(payload), payload_length);
    string result = "";

    // Filter ONLY HTTP Requests (GET, POST, PUT). Ignore Server responses (HTML).
    if (data.compare(0, 4, "GET ") == 0 || 
        data.compare(0, 5, "POST ") == 0 || 
        data.compare(0, 4, "PUT ") == 0) {
        
        // 1. Request Line: Which page and parameters? (e.g., GET /login.php?user=admin)
        size_t first_line_end = data.find("\r\n");
        if (first_line_end != string::npos) {
            result += "Request Line  : " + data.substr(0, first_line_end) + "\n";
        }

        // 2. Cookies: Are session tokens or login cookies leaking?
        size_t cookie_pos = data.find("Cookie: ");
        if (cookie_pos != string::npos) {
            size_t end_pos = data.find("\r\n", cookie_pos);
            if (end_pos != string::npos) {
                result += "Session Info  : " + data.substr(cookie_pos, end_pos - cookie_pos) + "\n";
            }
        }

        // 3. POST Data (Body): Passwords, API JSON data, credit cards entered in forms
        size_t body_pos = data.find("\r\n\r\n");
        if (body_pos != string::npos && body_pos + 4 < data.length()) {
            string body = data.substr(body_pos + 4);
            if (!body.empty()) {
                string clean_body = "";
                // For Machine Learning (NLP) analysis, the first 500 bytes are usually enough
                int limit = (body.length() > 500) ? 500 : body.length(); 
                for(int i=0; i<limit; i++) {
                    if(isprint(body[i])) clean_body += body[i];
                    else clean_body += ".";
                }
                result += "Outbound Data : " + clean_body + "\n";
            }
        }
    }
    return result;
}

// --- HTTPS TLS SNI PARSER ---
// Extracts the target website name (SNI) from an encrypted HTTPS Handshake
string parse_tls_sni(const u_char* payload, int payload_length) {
    // Check if packet is big enough for a TLS Client Hello
    if (payload_length < 43) return "";
    
    // Check if it is a TLS Handshake (0x16) and Client Hello (0x01)
    if (payload[0] != 0x16) return "";
    if (payload[5] != 0x01) return "";
    
    // Jump to dynamic fields (Skip fixed headers)
    int pos = 43; 
    
    // Skip Session ID, Cipher Suites, and Compression Methods
    if (pos >= payload_length) return "";
    int session_id_len = payload[pos];
    pos += 1 + session_id_len;
    
    if (pos + 1 >= payload_length) return "";
    int cipher_suites_len = (payload[pos] << 8) | payload[pos+1];
    pos += 2 + cipher_suites_len;
    
    if (pos >= payload_length) return "";
    int comp_methods_len = payload[pos];
    pos += 1 + comp_methods_len;
    
    // Get Extensions Length
    if (pos + 1 >= payload_length) return "";
    int extensions_len = (payload[pos] << 8) | payload[pos+1];
    pos += 2;
    
    int end_pos = pos + extensions_len;
    if (end_pos > payload_length) end_pos = payload_length;
    
    // Loop through extensions to find SNI (Type 0x0000)
    while (pos + 3 < end_pos) {
        int ext_type = (payload[pos] << 8) | payload[pos+1];
        int ext_len = (payload[pos+2] << 8) | payload[pos+3];
        pos += 4;
        
        // If we found the SNI extension...
        if (ext_type == 0x0000) { 
            if (pos + 4 < end_pos) {
                int list_len = (payload[pos] << 8) | payload[pos+1];
                int type = payload[pos+2];
                int name_len = (payload[pos+3] << 8) | payload[pos+4];
                
                // Read and return the website name!
                if (type == 0 && pos + 5 + name_len <= end_pos) {
                    string sni = "";
                    for (int i = 0; i < name_len; i++) sni += payload[pos + 5 + i];
                    return sni;
                }
            }
        }
        // Jump to the next extension if this one is not SNI
        pos += ext_len; 
    }
    return "";
}


// --- CORE PACKET PROCESSOR ---
// This function runs every time a new packet is caught
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    pcap_dumper_t *dumper = (pcap_dumper_t *)user_data;
    pcap_dump((u_char *)dumper, pkthdr, packet); // Save packet to PCAP file
    
    stringstream ss; // Smart Buffer: We write outputs here first instead of screen
    bool is_important = false; // Flag to decide if we should print this packet

    ss << "Packet Caught! Length : " << pkthdr->len << " bytes." << endl << endl;

    // --- LAYER 2: ETHERNET HEADER ---
    struct ether_header *eth_header = (struct ether_header *) packet;
    
    ss << "Source MAC      : " << ether_ntoa((struct ether_addr *)eth_header->ether_shost) << endl;
    ss << "Destination MAC : " << ether_ntoa((struct ether_addr *)eth_header->ether_dhost) << endl;
    ss << "-----------------------------------------------------------------" << endl;
    
    // Check next layer protocol (IPv4, IPv6, or ARP)
    uint16_t ether_type = ntohs(eth_header->ether_type);

    // =================================================================
    // ENGINE 1: IPv4 PARSING
    // =================================================================
    if (ether_type == ETHERTYPE_IP) { 
        ss << "IP Version      : IPv4" << endl;
        
        // Move pointer past Ethernet header to access IPv4 header
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));

        string source_ip = inet_ntoa(ip_header->ip_src);
        string dest_ip = inet_ntoa(ip_header->ip_dst);

        ss << "Source IP       : " << source_ip << endl;
        ss << "Destination IP  : " << dest_ip << endl;
        ss << "-----------------------------------------------------------------" << endl;

        // --- LAYER 4: TRANSPORT PROTOCOLS (TCP) ---
        if (ip_header->ip_p == IPPROTO_TCP){
            ss << "Protocol        : TCP" << endl;

            // Move Pointer from IP header to TCP header
            int ip_header_length = ip_header->ip_hl * 4;
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header_length);
            
            int tcp_header_length = tcp_header->doff * 4;
            uint16_t src_port = ntohs(tcp_header->source);
            uint16_t dst_port = ntohs(tcp_header->dest);
            
            ss << "Source Port     : " << src_port << endl;
            ss << "Dest Port       : " << dst_port << endl;

            // Calculate where the actual data (payload) starts
            int total_headers_size = sizeof(struct ether_header) + ip_header_length + tcp_header_length;
            int payload_length = pkthdr->caplen - total_headers_size;

            if (payload_length > 0){
                const u_char *payload = packet + total_headers_size;
                
                // --- DPI: HTTP (Port 80) ---
                if (src_port == 80 || dst_port == 80) {
                    ss << "App Protocol    : HTTP (Unencrypted Web)" << endl;
                    
                    string host = parse_http_host(payload, payload_length);
                    if (!host.empty()) {
                        is_important = true; // We caught a target!
                        ss << COLOR_GREEN << "🎯 Target Host   : " << host << COLOR_RESET << endl;
                    }
                    
                    // NEW/FIXED: Check if packet is OUTBOUND (leaving our machine on port 80)
                    if (dst_port == 80) {
                        string outbound_data = parse_outbound_http(payload, payload_length);
                        if (!outbound_data.empty()) {
                            is_important = true; // Make sure it prints on screen!
                            ss << COLOR_RED << "🚨 DATA LEAK DETECTED (Outbound Traffic)!" << COLOR_RESET << endl;
                            ss << COLOR_YELLOW << outbound_data << COLOR_RESET;
                        }
                    }
                }
                // --- DPI: HTTPS / TLS SNI (Port 443) ---
                else if (src_port == 443 || dst_port == 443) {
                    ss << "App Protocol    : HTTPS (Encrypted TLS)" << endl;
                    string sni = parse_tls_sni(payload, payload_length);
                    if (!sni.empty()) {
                        is_important = true; // We caught a target!
                        ss << COLOR_CYAN << "🔒 SNI (Target)  : " << sni << COLOR_RESET << endl;
                    }
                }
                else {
                    ss << "Payload (" << payload_length << " bytes)" << endl;
                }
            }
            ss << endl;
        }
        // --- LAYER 4: TRANSPORT PROTOCOLS (UDP) ---
        else if (ip_header->ip_p == IPPROTO_UDP) {
            ss << "Protocol        : UDP" << endl;

            // Move pointer from IP header to UDP header
            int ip_header_length = ip_header->ip_hl * 4;
            struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_header_length);

            // Convert ports to host byte order
            uint16_t src_port = ntohs(udp_header->source);
            uint16_t dst_port = ntohs(udp_header->dest);

            ss << "Source Port     : " << src_port << endl;
            ss << "Dest Port       : " << dst_port << endl;

            // --- DPI: DNS (Port 53) ---
            if (src_port == 53 || dst_port == 53) {
                ss << "App Protocol    : DNS (Domain Name System)" << endl;
                int total_headers_size = sizeof(struct ether_header) + ip_header_length + sizeof(struct udphdr);
                int payload_length = pkthdr->caplen - total_headers_size;

                // DNS header is 12 bytes long
                if (payload_length >= 12) {
                    const u_char *dns_payload = packet + total_headers_size;
                    int offset = 12; // Skip DNS header to reach website name

                    string queried_domain = parse_dns_name(dns_payload, offset, payload_length);

                    if (!queried_domain.empty() && queried_domain != "<compressed>") {
                         is_important = true;
                         ss << COLOR_YELLOW << "🌍 DNS Query     : " << queried_domain << COLOR_RESET << endl;
                    }
                }
            }
            // --- DPI: DHCP (Ports 67 & 68) ---
            else if (src_port == 67 || dst_port == 67 || src_port == 68 || dst_port == 68) {
                ss << "App Protocol    : DHCP (Dynamic Host Configuration Protocol)" << endl;

                int total_headers_size = sizeof(struct ether_header) + ip_header_length + sizeof(struct udphdr);
                int payload_length = pkthdr->caplen - total_headers_size;

                if (payload_length >= sizeof(struct dhcp_header)) {
                    is_important = true; // DHCP traffic is always important

                    const u_char *dhcp_payload = packet + total_headers_size;
                    struct dhcp_header *dhcp = (struct dhcp_header *)dhcp_payload;

                    ss << "DHCP OpCode     : " << (int)dhcp->op;
                    if (dhcp->op == 1) ss << " (Boot Request / Client asking for IP)" << endl;
                    else if (dhcp->op == 2) ss << " (Boot Reply / Server offering IP)" << endl;
                    else ss << " (Unknown)" << endl;

                    ss << "Transaction ID  : 0x" << hex << ntohl(dhcp->xid) << dec << endl;
                    ss << "Client IP       : " << inet_ntoa(dhcp->ciaddr) << endl;
                    ss << COLOR_RED << "🔥 Offered IP    : " << inet_ntoa(dhcp->yiaddr) << COLOR_RESET << endl;
                    ss << "Server IP       : " << inet_ntoa(dhcp->siaddr) << endl;
                }
            }
            ss << endl;
        }
        else if (ip_header->ip_p == IPPROTO_ICMP) {
            ss << "Protocol        : ICMP" << endl << endl;
        }
    } 
    // =================================================================
    // ENGINE 2: IPv6 PARSING
    // =================================================================
    else if (ether_type == ETHERTYPE_IPV6) {
        ss << "IP Version      : IPv6" << endl;
        
        struct ip6_hdr *ipv6_header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));

        char src_ip6[INET6_ADDRSTRLEN];
        char dst_ip6[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6, &(ipv6_header->ip6_src), src_ip6, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), dst_ip6, INET6_ADDRSTRLEN);

        ss << "Source IP       : " << src_ip6 << endl;
        ss << "Destination IP  : " << dst_ip6 << endl;
        ss << "-----------------------------------------------------------------" << endl;

        uint8_t next_header = ipv6_header->ip6_nxt;

        // --- LAYER 4: TRANSPORT PROTOCOLS (IPv6) ---
        if (next_header == IPPROTO_TCP) {
            ss << "Protocol        : TCP" << endl;
            int ip_header_length = 40; // IPv6 header is exactly 40 bytes
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header_length);
            int tcp_header_length = tcp_header->doff * 4;

            uint16_t src_port = ntohs(tcp_header->source);
            uint16_t dst_port = ntohs(tcp_header->dest);

            int total_headers_size = sizeof(struct ether_header) + ip_header_length + tcp_header_length;
            int payload_length = pkthdr->caplen - total_headers_size;

            if (payload_length > 0) {
                const u_char *payload = packet + total_headers_size;

                if (src_port == 80 || dst_port == 80) {
                    ss << "App Protocol    : HTTP" << endl;
                    string host = parse_http_host(payload, payload_length);
                    if (!host.empty()) {
                        is_important = true;
                        ss << COLOR_GREEN << "🎯 Target Host   : " << host << COLOR_RESET << endl;
                    }
                }
                else if (src_port == 443 || dst_port == 443) {
                    ss << "App Protocol    : HTTPS (TLS)" << endl;
                    string sni = parse_tls_sni(payload, payload_length);
                    if (!sni.empty()) {
                        is_important = true;
                        ss << COLOR_CYAN << "🔒 SNI (Target)  : " << sni << COLOR_RESET << endl;
                    }
                }
            }
            ss << endl;
        }
        else if (next_header == IPPROTO_UDP) {
            ss << "Protocol        : UDP" << endl;
            // Similar logic for IPv6 UDP could be added here
            ss << endl;
        }
        else if (next_header == IPPROTO_ICMPV6) ss << "Protocol        : ICMPv6" << endl << endl;
        else ss << "Protocol        : Other IPv6 Extension" << endl << endl;
    } 
    // =================================================================
    // ENGINE 3: ARP PARSING
    // =================================================================
    else if (ether_type == ETHERTYPE_ARP) {
        ss << "Protocol        : ARP (Address Resolution Protocol)" << endl;
        
        struct ether_arp *arp_header = (struct ether_arp *)(packet + sizeof(struct ether_header));
        uint16_t op = ntohs(arp_header->arp_op);
        
        if (op == ARPOP_REQUEST) ss << "Operation       : ARP Request (Who has this IP?)" << endl;
        else if (op == ARPOP_REPLY) ss << "Operation       : ARP Reply (I have this IP!)" << endl;
        else ss << "Operation       : Unknown (" << op << ")" << endl;

        char sender_ip[INET_ADDRSTRLEN];
        char target_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, arp_header->arp_spa, sender_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, arp_header->arp_tpa, target_ip, INET_ADDRSTRLEN);

        ss << "-----------------------------------------------------------------" << endl;
        ss << "Sender MAC      : " << ether_ntoa((struct ether_addr *)arp_header->arp_sha) << endl;
        ss << "Sender IP       : " << sender_ip << endl;
        ss << "Target MAC      : " << ether_ntoa((struct ether_addr *)arp_header->arp_tha) << endl;
        ss << "Target IP       : " << target_ip << endl;
    }
    else {
        ss << " -> Not an IPv4, IPv6, or ARP packet" << endl;
    }
    ss << "=================================================================" << endl << endl;

    // --- DECISION TIME: PRINT TO SCREEN? ---
    // If user selected Verbose (V), print everything.
    // If user selected Targeted (T), print ONLY if it is important!
    if (verbose_mode || is_important) {
        cout << ss.str();
    }
}

int main(int argc, char *argv[]) {
    signal(SIGINT, signal_handler);

    string filter_input = "";
    string filename = "";
    string mode_input = "";
    string base_path = ""; 

    // Get the folder path from run.sh for Docker mapping
    if (argc >= 2) {
        base_path = argv[1];
    }

    // --- INTERACTIVE UI SETUP ---
    cout << "=================================================================" << endl;
    cout << "                 C++ PACKET SNIFFER INITIALIZED                  " << endl;
    cout << "=================================================================" << endl;

    // --- NEW: OUTPUT MODE SELECTION ---
    cout << "Select Output Mode:" << endl;
    cout << "  [V] Verbose Mode  (Show absolutely ALL captured packets)" << endl;
    cout << "  [T] Targeted Mode (Show ONLY important data like DNS, DHCP, HTTP, SNI)" << endl;
    cout << "Enter your choice (V or T): ";
    getline(cin, mode_input);
    
    // Check if user selected Targeted Mode
    if (mode_input == "T" || mode_input == "t") {
        verbose_mode = false;
        cout << COLOR_GREEN << "-> Targeted Mode ENABLED. Filtering out noise..." << COLOR_RESET << endl << endl;
    } else {
        cout << "-> Verbose Mode ENABLED. Showing everything." << endl << endl;
    }

    cout << "Enter BPF filter (e.g., 'tcp port 80', 'icmp', 'ip6', 'arp')." << endl;
    cout << "Leave blank to capture ALL traffic: ";
    getline(cin, filter_input);

    cout << "Enter output file name (Leave blank for 'capture.pcap'): ";
    getline(cin, filename);
    cout << endl; 

    // Use default filename if empty
    if (filename.empty()) {
        filename = "capture.pcap";
    } else if (filename.find(".pcap") == string::npos) {
        filename += ".pcap";
    }

    string full_filepath = base_path + filename;

    // --- DEVICE DISCOVERY ---
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *device;

    if (pcap_findalldevs(&alldevs, errbuf) == -1){
        cerr << "Error finding devices: " << errbuf << endl;
        return 1;
    }

    device = alldevs; // Defaulting to the first available interface
    if (device == nullptr){
        cerr << "No devices found." << endl;
        return 1;
    }

    cout << "Opening Device : "<< device->name << endl;

    // Open interface in promiscuous mode (1)
    global_handle = pcap_open_live(device->name, 65535, 1, 1000, errbuf);
    if (global_handle == nullptr){
        cout << "Couldn't open device : " << errbuf << endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    // --- BPF FILTER COMPILATION ---
    struct bpf_program fp;

    if (!filter_input.empty()) {
        cout << "Compiling filter : " << filter_input << endl;

        if (pcap_compile(global_handle, &fp, filter_input.c_str(), 0 , PCAP_NETMASK_UNKNOWN) == -1 ) {
                cerr << "Error : Couldn't compile filter. " << endl;
                cerr << "Details :  " << pcap_geterr(global_handle) << endl;
                pcap_close(global_handle);
                pcap_freealldevs(alldevs);
                return 1;
        }

        if (pcap_setfilter(global_handle, &fp) == -1) {
                cerr << "Error : Couldn't apply filter : " << pcap_geterr(global_handle) << endl;
                pcap_close(global_handle);
                pcap_freealldevs(alldevs);
                return 1;
        }
        cout << "Filter applied successfully!" << endl;
    } 
    else {
        cout << "No filter applied. Capturing all traffic." << endl;
    }

    // --- PCAP FILE CREATION ---
    pcap_dumper_t *dumper = pcap_dump_open(global_handle, full_filepath.c_str());
    if (dumper == nullptr) {
        cerr << "Error: Couldn't create pcap file: " << full_filepath << endl;
        pcap_close(global_handle);
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Isolate filename for clean display output
    string display_filename = full_filepath;
    size_t last_slash = full_filepath.find_last_of("/");
    if (last_slash != string::npos) {
        display_filename = full_filepath.substr(last_slash + 1);
    }

    cout << "Saving captured packets to '" << display_filename << "'..." << endl;
    cout << "=================================================================" << endl << endl;

    // --- START MAIN CAPTURE LOOP ---
    pcap_loop(global_handle, 0, packet_handler, (u_char *)dumper);
    
    // --- CLEANUP ---
    pcap_dump_close(dumper);
    pcap_close(global_handle);
    pcap_freealldevs(alldevs);

    cout << "Sniffing is Done. Session Closed Successfully." << endl;
    return 0;
}
