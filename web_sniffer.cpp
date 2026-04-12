#include <iostream>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <cctype>
#include <csignal>

using namespace std;

pcap_t *global_handle = nullptr; 

void signal_handler(int signum) {
	cout << endl << "A shutdown signal has been received! The program is shutting down gracefully ... " << endl;
    	if (global_handle != nullptr) {
        	pcap_breakloop(global_handle);
    	}
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    	// pkthdr (Packet Header), libpcap's own structure that holds info like packet length and time
    
    	pcap_dumper_t *dumper = (pcap_dumper_t *)user_data;
    
    	pcap_dump((u_char *)dumper, pkthdr, packet);
    
    	cout << "Packet Caught! Length : " << pkthdr->len << " bytes." << endl << endl;

    	//MAC ADDRESS
    	struct ether_header *eth_header = (struct ether_header *) packet;//Converts packets to ethernet headers.
    
    	cout << "Source MAC      : " << ether_ntoa((struct ether_addr *)eth_header->ether_shost) << endl;//Network to ASCII
    	cout << "Destination MAC : " << ether_ntoa((struct ether_addr *)eth_header->ether_dhost) << endl;
    	cout << "-------------------------------------------------------------------------" << endl;
    
    	//IP ADDRESS
    	if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) { //Checks if the protocol in the packet is IPv4. (Network To Host Short)
        	cout << " -> Not an ip packet" << endl;
        	cout << "-----------------------------------------------------------------" << endl;
        	return;
    	}

    	struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));//Moving pointer to the 15th byte (usually sizeof(ether_header) = 14) where IP informations begins.

    	string source_ip = inet_ntoa(ip_header->ip_src);
    	string dest_ip = inet_ntoa(ip_header->ip_dst);

    	cout << "Source IP       : " << source_ip << endl;
    	cout << "Destination IP  : " << dest_ip << endl;
    	cout << "-----------------------------------------------------------------" << endl;

    	//PROTOCOL TYPE AND PAYLOAD EXTRACTION
    	string protocol_type = "Unknown";

    	if (ip_header->ip_p == IPPROTO_TCP){
        	protocol_type = "TCP";
        	cout << "Protocol : " << protocol_type << endl;

        	int ip_header_length = ip_header->ip_hl * 4;

	        struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header_length);//Moving pointer to the TCP header.

        	int tcp_header_length = tcp_header->doff * 4;

	        int total_headers_size = sizeof(struct ether_header) + ip_header_length + tcp_header_length;
	
	        int payload_length = pkthdr->caplen - total_headers_size;

        	if (payload_length > 0){
            		const u_char *payload = packet + total_headers_size;

            		cout << "Payload (" << payload_length << " bytes)" << endl;
            		cout << "[ ";
            
            		for (int i = 0; i < payload_length; i++){
                		if (isprint(payload[i])){
                    			cout << payload[i];
                		}
                		else {
                    			cout << ".";
                			}
            		}
            		cout << " ]" << endl << endl;
		}
        	else {
			cout << "Payload : (No Data) " << endl << endl;
        	}
    	}
    	else if (ip_header->ip_p == IPPROTO_UDP) {
        	protocol_type = "UDP";
        	cout << "Protocol : " << protocol_type << endl << endl;
    	}
    	else if (ip_header->ip_p == IPPROTO_ICMP) {
        	protocol_type = "ICMP";
        	cout << "Protocol : " << protocol_type << endl << endl;
    	}
	cout << "-----------------------------------------------------------------" << endl << endl;
}

int main(int argc, char *argv[]) {
    	signal(SIGINT, signal_handler);

    	string filename = "capture.pcap"; //Default file name
    	string filter_input = "";         //Default filter

    	if (argc >= 2) {
        	filename = argv[1];
        	//File name correction.
        	if (filename.find(".pcap") == string::npos) {
            		filename += ".pcap";
        	}
    	}
       	else {
        	cout << "Warning : Missing arguments. Default settings are accepted (capture.pcap , No filter)." << endl;
        	cout << "Recommended Usage : sudo ./web_sniffer <file_name> <filters>" << endl;
 	}	

	if (argc >= 3) {
        	for (int i = 2; i < argc; i++) {
            		filter_input += argv[i];
			if (i < argc - 1) {
                		filter_input += " "; 
			}
        	}
    	}

    	char errbuf[PCAP_ERRBUF_SIZE];
    	pcap_if_t *alldevs;
    	pcap_if_t *device;

    	//FINDING DEVICES
    	if (pcap_findalldevs(&alldevs, errbuf) == -1){
        	return 1;
    	}
    
    	device = alldevs;
    
    	if (device == nullptr){
        	return 1;
    	}

    	cout << "Opening Device : "<< device->name << endl;

    	global_handle = pcap_open_live(device->name, 65535, 1, 1000, errbuf);
    
    	if (global_handle == nullptr){
        	cout << "Couldn't open device : " << errbuf << endl;
        	return 1;
    	}

    	//FILTERING
    	struct bpf_program fp;

	if (!filter_input.empty()) {
	cout << "Compiling filter : " << filter_input << endl;

        	if (pcap_compile(global_handle, &fp, filter_input.c_str(), 0 , PCAP_NETMASK_UNKNOWN) == -1 ) {
            		cerr << "Error : Couldn't compile filter. " << endl;
            		cerr << "Details :  " << pcap_geterr(global_handle) << endl;
            		return 1;
        	}
        
		if (pcap_setfilter(global_handle, &fp) == -1) {
            		cerr << "Error : Couldn't apply filter : " << pcap_geterr(global_handle) << endl;
            		return 1;
        	}

        	cout << "Filter applied successfully!" << endl;
    	} 
    	else {
        	cout << "No filter applied. Capturing all traffic." << endl;
   	}
    
    	//CREATING PCAP FILE
    	pcap_dumper_t *dumper = pcap_dump_open(global_handle, filename.c_str());

    	if (dumper == nullptr) {
        	cerr << "Error: Couldn't create pcap file: " << filename << endl;
        	return 1;
    	}

    	cout << "Saving captured packets to '" << filename << "'..." << endl;
    	cout << "=================================================================" << endl << endl;

	 //START LISTENING
   	 pcap_loop(global_handle, 0, packet_handler, (u_char *)dumper);
    
    	//CLEAN UP AND CLOSE
    	pcap_dump_close(dumper);
    	pcap_close(global_handle);
	pcap_freealldevs(alldevs);

	cout << "Sniffing is Done. Session Closed Successfully." << endl;
    	return 0;
}
