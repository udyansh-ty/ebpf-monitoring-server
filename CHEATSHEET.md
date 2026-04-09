# eBPF Masquerade Validation Cheatsheet

## 1) One-command setup (host machine)

From repo root:

```bash
./masquerade-vm-setup.sh
```

This provisions a fresh VM named `masquerade-vm`, builds binaries, starts services, and configures `nsmasq` namespace with `POSTROUTING MASQUERADE`.

## 2) Open VM shell

```bash
multipass shell masquerade-vm
cd /home/ubuntu/ebpf-monitoring-server
```

## 3) Check monitor processes

```bash
pgrep -af ebpf-aggregator
pgrep -af ebpf-server
```

Expected:
- one `./bin/ebpf-aggregator ...`
- one `./bin/ebpf-server ...`

## 4) Reset `ebpf_meta_window` (manual clean run)

```bash
export PGPASSWORD=ebpfaggpass
psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -c "ALTER TABLE ebpf_meta_window DISABLE TRIGGER trg_prevent_ebpf_meta_window_delete;"
psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -c "TRUNCATE TABLE ebpf_meta_window;"
psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -c "ALTER TABLE ebpf_meta_window ENABLE TRIGGER trg_prevent_ebpf_meta_window_delete;"
```

## 5) Generate traffic from masqueraded namespace

### 5.1 IPv4 ICMP + TCP (no DNS dependency)

```bash
for i in {1..10}; do
  sudo ip netns exec nsmasq ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1 || true
  sudo ip netns exec nsmasq curl -sS --max-time 5 http://1.1.1.1 >/dev/null || true
  sleep 1
done
```

### 5.2 DNS-backed HTTPS (if resolver reachable)

```bash
for i in {1..5}; do
  sudo ip netns exec nsmasq curl -sS --max-time 5 https://github.com >/dev/null || true
  sudo ip netns exec nsmasq curl -sS --max-time 5 https://google.com >/dev/null || true
  sleep 1
done
```

### 5.3 IPv6 traffic

```bash
sudo ip netns exec nsmasq ping -6 -c 3 2001:4860:4860::8888 || true
```

## 6) Simulate forwarding drop events

```bash
IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
sudo iptables -I FORWARD 1 -i veth-host -o "$IFACE" -d 1.1.1.1 -j DROP
sudo ip netns exec nsmasq ping -c 3 -W 1 1.1.1.1 || true
sudo iptables -D FORWARD -i veth-host -o "$IFACE" -d 1.1.1.1 -j DROP
```

## 7) Real-time DB verification

### 7.1 Total row growth

```bash
watch -n 2 "PGPASSWORD=ebpfaggpass psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -c 'SELECT COUNT(*) FROM ebpf_meta_window;'"
```

Expected: count increases after traffic generation.

### 7.2 Latest summarized rows

```bash
PGPASSWORD=ebpfaggpass psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -c "
SELECT src_ip,dst_ip,src_port,dst_port,interface_name,protocol,
       packets_in,packets_out,bytes_in,bytes_out,active_seconds,
       session_count,first_seen_epoch,last_seen_epoch
FROM ebpf_meta_window
ORDER BY last_seen_epoch DESC
LIMIT 25;"
```

Expected pattern:
- `src_ip` on egress often appears as VM host IP (masqueraded source), not `10.200.1.2`
- `protocol` includes `icmp`, `udp`, `tcp`, and optionally `icmpv6`
- `packets_*`, `bytes_*`, `active_seconds` should be non-zero for active flows
- repeated same 5-tuple keys are merged into summarized rows

### 7.3 Recent rows only

```bash
PGPASSWORD=ebpfaggpass psql -h 127.0.0.1 -U ebpfagg -d ebpf_agg -c "
WITH now_epoch AS (SELECT extract(epoch from now())::bigint AS n)
SELECT src_ip,dst_ip,protocol,packets_out,bytes_out,last_seen_epoch
FROM ebpf_meta_window, now_epoch
WHERE last_seen_epoch >= now_epoch.n - 120
ORDER BY last_seen_epoch DESC;"
```

## 8) Logs

```bash
tail -f /tmp/ebpf-server.log
tail -f /tmp/ebpf-aggregator.log
```

Useful log indicators:
- `Forward-flow monitoring program attached and active`
- `STORED EVENT: type=forward_flow`

## 9) Quick troubleshooting

- `zero rows`: ensure traffic was generated after truncate and wait 2-4 seconds for flush.
- `dns curl timeout`: continue with IP-only traffic (`ping 1.1.1.1`, `curl http://1.1.1.1`) to validate forwarding path.
- `server exited`: inspect `/tmp/ebpf-server.log` for eBPF attach/helper errors.
