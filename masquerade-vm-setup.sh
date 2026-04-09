#!/usr/bin/env bash
set -euo pipefail

VM_NAME="${VM_NAME:-masquerade-vm}"
CPUS="${CPUS:-4}"
MEMORY="${MEMORY:-8G}"
DISK="${DISK:-30G}"
VM_REPO_DIR="/home/ubuntu/ebpf-monitoring-server"

HOST_REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() {
  printf '[masquerade-vm-setup] %s\n' "$*"
}

if ! command -v multipass >/dev/null 2>&1; then
  echo 'multipass is required but not installed' >&2
  exit 1
fi

if multipass info "$VM_NAME" >/dev/null 2>&1; then
  log "Recreating existing VM: $VM_NAME"
  multipass stop "$VM_NAME" || true
  multipass delete "$VM_NAME" || true
  multipass purge || true
fi

log "Launching VM $VM_NAME"
multipass launch 24.04 --name "$VM_NAME" --cpus "$CPUS" --memory "$MEMORY" --disk "$DISK"

log 'Syncing repository into VM'
multipass exec "$VM_NAME" -- bash -lc "rm -rf '$VM_REPO_DIR' && mkdir -p /home/ubuntu"
multipass transfer -r "$HOST_REPO_DIR" "$VM_NAME:/home/ubuntu/"

log 'Installing VM dependencies'
multipass exec "$VM_NAME" -- bash -lc 'set -euo pipefail; sudo apt-get update; sudo DEBIAN_FRONTEND=noninteractive apt-get install -y golang-go clang llvm libbpf-dev make postgresql iproute2 iptables curl ca-certificates'

log 'Building eBPF objects and binaries'
multipass exec "$VM_NAME" -- bash -lc "set -euo pipefail; cd '$VM_REPO_DIR'; make bpf; go build -buildvcs=false -o ./bin/ebpf-aggregator ./cmd/aggregator/; go build -buildvcs=false -o ./bin/ebpf-server ./cmd/server/"

log 'Configuring PostgreSQL'
multipass exec "$VM_NAME" -- bash -lc "set -euo pipefail; sudo systemctl enable --now postgresql; sudo -u postgres psql -tc \"SELECT 1 FROM pg_roles WHERE rolname='ebpfagg'\" | grep -q 1 || sudo -u postgres psql -c \"CREATE USER ebpfagg WITH PASSWORD 'ebpfaggpass'\"; sudo -u postgres psql -tc \"SELECT 1 FROM pg_database WHERE datname='ebpf_agg'\" | grep -q 1 || sudo -u postgres psql -c \"CREATE DATABASE ebpf_agg OWNER ebpfagg\""

log 'Starting aggregator and server'
multipass exec "$VM_NAME" -- bash -lc "set -euo pipefail; cd '$VM_REPO_DIR'; pkill -f ebpf-aggregator || true; pkill -f ebpf-server || true; nohup env DB_URL='postgres://ebpfagg:ebpfaggpass@127.0.0.1:5432/ebpf_agg?sslmode=disable' ./bin/ebpf-aggregator -addr :8081 -meta-flush-interval 2s >/tmp/ebpf-aggregator.log 2>&1 & sleep 1; nohup sudo env AGGREGATOR_URL='http://127.0.0.1:8081' ./bin/ebpf-server -addr :8080 >/tmp/ebpf-server.log 2>&1 & sleep 2"

log 'Configuring namespace + masquerade rules'
multipass exec "$VM_NAME" -- bash -lc 'set -euo pipefail; IFACE=$(ip route show default | awk '"'"'/default/ {print $5; exit}'"'"'); sudo ip netns del nsmasq 2>/dev/null || true; sudo ip link del veth-host 2>/dev/null || true; sudo ip netns add nsmasq; sudo ip link add veth-host type veth peer name veth-ns; sudo ip link set veth-ns netns nsmasq; sudo ip addr add 10.200.1.1/24 dev veth-host; sudo ip link set veth-host up; sudo ip netns exec nsmasq ip addr add 10.200.1.2/24 dev veth-ns; sudo ip netns exec nsmasq ip link set lo up; sudo ip netns exec nsmasq ip link set veth-ns up; sudo ip netns exec nsmasq ip route add default via 10.200.1.1; sudo mkdir -p /etc/netns/nsmasq; echo nameserver 8.8.8.8 | sudo tee /etc/netns/nsmasq/resolv.conf >/dev/null; sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null; sudo iptables -t nat -D POSTROUTING -s 10.200.1.0/24 -o "$IFACE" -j MASQUERADE 2>/dev/null || true; sudo iptables -D FORWARD -i veth-host -o "$IFACE" -j ACCEPT 2>/dev/null || true; sudo iptables -D FORWARD -i "$IFACE" -o veth-host -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true; sudo iptables -t nat -A POSTROUTING -s 10.200.1.0/24 -o "$IFACE" -j MASQUERADE; sudo iptables -A FORWARD -i veth-host -o "$IFACE" -j ACCEPT; sudo iptables -A FORWARD -i "$IFACE" -o veth-host -m state --state RELATED,ESTABLISHED -j ACCEPT; echo "Interface used for MASQUERADE: $IFACE"'

log 'Validation quick check'
multipass exec "$VM_NAME" -- bash -lc "set -euo pipefail; pgrep -af ebpf-aggregator >/dev/null; pgrep -af ebpf-server >/dev/null; echo 'Processes are running'; export PGPASSWORD='ebpfaggpass'; psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -c 'SELECT COUNT(*) AS rows FROM ebpf_meta_window;'"

cat <<INFO

Setup complete.

Open shell:
  multipass shell $VM_NAME

Inside VM, generate namespace traffic:
  sudo ip netns exec nsmasq ping -c 5 1.1.1.1
  sudo ip netns exec nsmasq curl -sS --max-time 5 http://1.1.1.1 >/dev/null

Inside VM, verify DB:
  export PGPASSWORD=ebpfaggpass
  psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -c "SELECT COUNT(*) FROM ebpf_meta_window;"
  psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -c "SELECT src_ip,dst_ip,protocol,packets_out,bytes_out,last_seen_epoch FROM ebpf_meta_window ORDER BY last_seen_epoch DESC LIMIT 20;"

Logs:
  tail -f /tmp/ebpf-server.log
  tail -f /tmp/ebpf-aggregator.log
INFO
