#!/usr/bin/env bash
set -euo pipefail

BACKEND_NS=xlb_backend
CLIENT_NS=xlb_client

HOST_LB_IF=xlb0
BACKEND_IF=xlb1
HOST_CLIENT_IF=xlc0
CLIENT_IF=xlc1

HOST_LB_IP=192.168.1.100/24
BACKEND_IP=192.168.1.101/24
HOST_CLIENT_IP=10.0.0.1/24
CLIENT_IP=10.0.0.2/24

echo "[*] Cleaning up any previous setup"
sudo ip link del "$HOST_LB_IF" 2>/dev/null || true
sudo ip link del "$HOST_CLIENT_IF" 2>/dev/null || true
sudo ip netns del "$BACKEND_NS" 2>/dev/null || true
sudo ip netns del "$CLIENT_NS" 2>/dev/null || true

echo "[*] Creating backend namespace and veth pair"
sudo ip netns add "$BACKEND_NS"
sudo ip link add "$HOST_LB_IF" type veth peer name "$BACKEND_IF"
sudo ip link set "$HOST_LB_IF" up
sudo ip addr add "$HOST_LB_IP" dev "$HOST_LB_IF"

sudo ip link set "$BACKEND_IF" netns "$BACKEND_NS"
sudo ip netns exec "$BACKEND_NS" ip link set lo up
sudo ip netns exec "$BACKEND_NS" ip link set "$BACKEND_IF" up
sudo ip netns exec "$BACKEND_NS" ip addr add "$BACKEND_IP" dev "$BACKEND_IF"

echo "[*] Creating client namespace and veth pair"
sudo ip netns add "$CLIENT_NS"
sudo ip link add "$HOST_CLIENT_IF" type veth peer name "$CLIENT_IF"
sudo ip link set "$HOST_CLIENT_IF" up
sudo ip addr add "$HOST_CLIENT_IP" dev "$HOST_CLIENT_IF"

sudo ip link set "$CLIENT_IF" netns "$CLIENT_NS"
sudo ip netns exec "$CLIENT_NS" ip link set lo up
sudo ip netns exec "$CLIENT_NS" ip link set "$CLIENT_IF" up
sudo ip netns exec "$CLIENT_NS" ip addr add "$CLIENT_IP" dev "$CLIENT_IF"
sudo ip netns exec "$CLIENT_NS" ip route add default via ${HOST_CLIENT_IP%/*}

echo "[*] Enabling IP forwarding and disabling rp_filter on host interfaces"
sudo sysctl -q -w net.ipv4.ip_forward=1 >/dev/null
sudo sysctl -q -w net.ipv4.conf.all.rp_filter=0 >/dev/null
sudo sysctl -q -w net.ipv4.conf.default.rp_filter=0 >/dev/null
sudo sysctl -q -w net.ipv4.conf."$HOST_LB_IF".rp_filter=0 >/dev/null
sudo sysctl -q -w net.ipv4.conf."$HOST_CLIENT_IF".rp_filter=0 >/dev/null

echo "[*] Adding host routes"
sudo ip route add 192.168.1.0/24 dev "$HOST_LB_IF" 2>/dev/null || true
sudo ip route add 10.0.0.0/24 dev "$HOST_CLIENT_IF" 2>/dev/null || true
sudo ip netns exec "$BACKEND_NS" ip route add 192.168.1.0/24 dev "$BACKEND_IF" 2>/dev/null || true
sudo ip netns exec "$BACKEND_NS" ip route add 10.0.0.0/24 via ${HOST_LB_IP%/*} dev "$BACKEND_IF" 2>/dev/null || true
sudo ip netns exec "$CLIENT_NS" ip route add 192.168.1.0/24 via ${HOST_CLIENT_IP%/*} dev "$CLIENT_IF" 2>/dev/null || true

echo "[*] Priming ARP tables"
ping -c1 -W1 192.168.1.101 >/dev/null || true
sudo ip netns exec "$BACKEND_NS" ping -c1 -W1 192.168.1.100 >/dev/null || true
sudo ip netns exec "$CLIENT_NS" ping -c1 -W1 10.0.0.1 >/dev/null || true

echo
echo "Environment ready:"
echo "  LB listen IP (host namespace): 192.168.1.100 on $HOST_LB_IF"
echo "  Backend namespace ($BACKEND_NS): 192.168.1.101 on $BACKEND_IF"
echo "    Run backend: sudo ip netns exec $BACKEND_NS nc -l 192.168.1.101 8080"
echo "  Client namespace ($CLIENT_NS): 10.0.0.2 on $CLIENT_IF"
echo "    Run client: sudo ip netns exec $CLIENT_NS curl http://192.168.1.100:80"
