# network-ninja-firewall-defense-hack
# 🛡️ Network Ninja’s Firewall Defense Hack (Mobile Version)

**Goal:** Detect and document Port Scan, SYN Flood, and DNS Tunneling using an Android phone (Termux).  
**Note:** pfSense/VLANs are out-of-scope on mobile; defenses are demonstrated via captures and IDS rules (or simulated alerts if Suricata unavailable).

## 🧪 What’s Included
- `rules/local.rules` – IDS rules (SYN flood, long DNS)
- `evidence/pcaps/` – portscan-before/after, synflood, dns-tunnel
- `evidence/alerts/` – synflood-alerts.json, dns-tunnel-alert.json
- `evidence/screenshots/` – terminal outputs & results
- `docs/slides.pdf` – 5-slide summary deck
- Demo video (≤30s): **[Watch here](https://drive.google.com/file/d/1VlWolB32qIuJLpn4gFspfkHd9ta5btKI/view?usp=drivesdk)**

## 🔁 Reproduce (copy–paste in Termux)
```bash
termux-setup-storage
pkg update && pkg upgrade -y
pkg install -y nmap hping3 tcpdump jq bind-tools

# (Optional) Suricata:
pkg install -y suricata || echo "No suricata; will use simulated alerts."

# Directories
mkdir -p ~/network-ninja/{rules,evidence/pcaps,evidence/alerts,evidence/screenshots}

# Rules
cat > ~/network-ninja/rules/local.rules << 'EOF'
alert tcp any any -> any any (msg:"Possible SYN Flood"; flags:S; threshold: type both, track by_src, count 50, seconds 10; sid:1000001; rev:1;)
alert dns any any -> any any (msg:"Suspicious DNS Query – Possible Tunneling"; pcre:"/.{50,}/"; sid:1000002; rev:1;)
EOF

# (If Suricata works)
suricata -S ~/network-ninja/rules/local.rules -i any \
 -c /data/data/com.termux/files/usr/etc/suricata/suricata.yaml \
 -l ~/network-ninja/evidence &

# Port scan (before)
tcpdump -i any -w ~/network-ninja/evidence/pcaps/portscan-before.pcap &
N1=$!; nmap -sS 127.0.0.1; kill $N1

# Port scan (after, simulated)
tcpdump -i any -w ~/network-ninja/evidence/pcaps/portscan-after.pcap &
N2=$!; nmap -sS 127.0.0.1; kill $N2

# SYN flood
tcpdump -i any -w ~/network-ninja/evidence/pcaps/synflood.pcap &
N3=$!; hping3 --flood -S -p 80 127.0.0.1; kill $N3

# Alerts (real if Suricata; else simulate)
jq 'select(.alert)' ~/network-ninja/evidence/eve.json \
 > ~/network-ninja/evidence/alerts/synflood-alerts.json 2>/dev/null \
 || echo '{"alert":"Possible SYN Flood (simulated)"}' > ~/network-ninja/evidence/alerts/synflood-alerts.json

# DNS tunnel (long query)
tcpdump -i any -w ~/network-ninja/evidence/pcaps/dns-tunnel.pcap &
N4=$!; dig $(printf 'a%.0s' {1..60}).example.com; kill $N4

jq 'select(.alert)' ~/network-ninja/evidence/eve.json \
 > ~/network-ninja/evidence/alerts/dns-tunnel-alert.json 2>/dev/null \
 || echo '{"alert":"Long DNS query detected (simulated)"}' > ~/network-ninja/evidence/alerts/dns-tunnel-alert.json
