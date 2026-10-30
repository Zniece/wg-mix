#!/usr/bin/env bash
# Test wg-quick as a pure listener (no peer Endpoint).
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EBPF="$ROOT/wgmix-ebpf"
WGMIX="$(cd "$ROOT/.." && pwd)/wgmix"
WGQUICK="$(cd "$ROOT/.." && pwd)/wg-quick"
NS1=wgl1ns
NS2=wgl2ns

[ "$(id -u)" = 0 ] || { echo "root required" >&2; exit 1; }
[ -x "$EBPF" ] || { echo "missing $EBPF" >&2; exit 1; }
[ -x "$WGMIX" ] || { echo "missing $WGMIX" >&2; exit 1; }
[ -f "$WGQUICK" ] || { echo "missing $WGQUICK" >&2; exit 1; }

mkdir -p /var/run/wireguard

cleanup() {
	set +e
	[ -f /tmp/wglB.pid ] && kill "$(cat /tmp/wglB.pid)" 2>/dev/null
	ip netns del "$NS1" 2>/dev/null
	ip netns del "$NS2" 2>/dev/null
	rm -f /tmp/wglB.pid /tmp/wglB.log /tmp/wgl0.conf /tmp/wglB.conf
}
trap cleanup EXIT

ip netns del "$NS1" 2>/dev/null || true
ip netns del "$NS2" 2>/dev/null || true
ip netns add "$NS1"
ip netns add "$NS2"
ip link add v1a type veth peer name v1b
ip link set v1a netns "$NS1"
ip link set v1b netns "$NS2"
ip -n "$NS1" addr add 10.99.0.1/24 dev v1a
ip -n "$NS2" addr add 10.99.0.2/24 dev v1b
ip -n "$NS1" link set lo up
ip -n "$NS2" link set lo up
ip -n "$NS1" link set v1a up
ip -n "$NS2" link set v1b up
# Pure listener has no peer Endpoint; give wg-quick a default route to derive
# the egress interface.
ip -n "$NS1" route add default via 10.99.0.2 dev v1a

k1=$(wg genkey); p1=$(printf '%s' "$k1" | wg pubkey)
k2=$(wg genkey); p2=$(printf '%s' "$k2" | wg pubkey)

cat >/tmp/wgl0.conf <<EOF
[Interface]
Address = 10.0.0.1/24
PrivateKey = $k1
ListenPort = 51820
WgBin = $EBPF

[Peer]
PublicKey = $p2
AllowedIPs = 10.0.0.2/32
EOF

cat >/tmp/wglB.conf <<EOF
[Interface]
PrivateKey = $k2
ListenPort = 51821
[Peer]
PublicKey = $p1
Endpoint = 10.99.0.1:51820
AllowedIPs = 10.0.0.1/32
PersistentKeepalive = 25
EOF

# Client side (userspace, has an Endpoint).
ip netns exec "$NS2" "$WGMIX" -f wgB >/tmp/wglB.log 2>&1 &
echo $! >/tmp/wglB.pid
for _ in $(seq 1 50); do
	ip -n "$NS2" link show wgB >/dev/null 2>&1 && break
	sleep 0.1
done
ip -n "$NS2" addr add 10.0.0.2/24 dev wgB
ip -n "$NS2" link set wgB up
ip netns exec "$NS2" wg setconf wgB /tmp/wglB.conf

# Listener side (no peer Endpoint).
echo "--- wg-quick up (listener) ---"
WG_MIX_XDP=skb nsenter --net="/var/run/netns/$NS1" bash "$WGQUICK" up /tmp/wgl0.conf || {
	echo "wg-quick up failed"
	cat /tmp/wglB.log
	exit 1
}
ip netns exec "$NS1" /usr/sbin/bpftool net

sleep 6
echo "--- ping from client to listener ---"
ip netns exec "$NS2" ping -c 2 -W 2 10.0.0.1 || true
echo "--- listener wg ---"
ip netns exec "$NS1" wg show wgl0
echo "--- status ---"
nsenter --net="/var/run/netns/$NS1" "$EBPF" status -iface v1a

echo "--- wg-quick down ---"
nsenter --net="/var/run/netns/$NS1" bash "$WGQUICK" down /tmp/wgl0.conf || true
