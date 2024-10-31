# TCP Hijacking in NAT-Enabled Wi-Fi Networks
The current version of the attack code, which can be used in different NAT-Enabled Wi-Fi networks including NAT44, NAT64, and NAT66.

### Threat model

The model consists of three hosts and one router, namely, a remote server, a victim client, an off-path attacker, and a vulnerable router. The router carries out NAT44, NAT66, or NAT64 and acts as the gateway to provide Internet services for the Wi-Fi network. The remote server may be a web application, an SSH or FTP server in different attack scenarios. The victim client (e.g., a mobile phone) is connected to the router to communicate with the remote server, i.e., visiting web pages, downloading files through FTP, or using the SSH service to control remote hosts. The off-path attacker is a malicious client who can connect to the same Wi-Fi network as the victim client.

### Requirement

* The attacker machine needs to install:
  * scapy 
  * libtins (http://libtins.github.io/download/)
    ```
    sudo apt install git libpcap-dev libssl-dev cmake build-essential scapy netcat-traditional
    git clone https://github.com/mfontanini/libtins.git
    cd libtins
    mkdir build
    cd build
    cmake ../ -DLIBTINS_ENABLE_CXX11=1
    make
    sudo make install
    sudo ldconfig
    ```


### Running the Full Attack Script (Take NAT44 as an example)
- First, on the remote server machine:
  * Open a TCP service for clients to connect, e.g., 80 for HTTP, 21 for FTP, 22 for SSH
  * Here we simulate it by netcat on TCP port 1000 (You need to configure the firewall rules to allow traffic in): run `sudo nc -lvnvp 1000`
  
- Second, on the victim machine:
  * Establish the TCP connection with the remote server (install netcat first: `sudo apt install netcat-traditional`): run `nc <remote_server_ip> 1000 -p 32800`
  * You can run `tcpdump/wireshark` to capture the packets and watch the source port, sequence number, and acknowledgment numbers of the TCP connection

- Third, on the local attacker machine:
  * `cd IPv4`
  * Rebuild all the attack scripts: `bash ./rebuild_all.sh`
  * `cd complete_attack`
  * Change `attack-ssh.sh` vars to appropriate values
  * `sudo bash attack-ssh.sh`





### Citations
```
@inproceedings{yang2024exploiting,
  title={Exploiting Sequence Number Leakage: TCP Hijacking in NAT-Enabled Wi-Fi Networks},
  author={Yang, Yuxiang and Feng, Xuewei and Li, Qi and Sun, Kun and Wang, Ziqiang and Xu, Ke},
  booktitle={Network and Distributed System Security (NDSS) Symposium},
  year={2024}
}

@journals{
  to-be-added
}
```
