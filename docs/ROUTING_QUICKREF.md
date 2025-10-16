# Quick Reference: VPN Routing Configuration

## 🚀 Quick Start

### Full Tunnel (Default)
```bash
sudo ./zig-out/bin/vpnclient --config config.json
```
ALL traffic goes through VPN.

### Split Tunnel
```bash
sudo VPN_SEND_ALL_TRAFFIC=0 ./zig-out/bin/vpnclient --config config.json
```
Only VPN network traffic goes through tunnel.

### Advanced Routing
```bash
sudo VPN_ADVANCED_ROUTING=1 \
     VPN_IPV4_INCLUDE="10.0.0.0/8,192.168.0.0/16" \
     VPN_IPV4_EXCLUDE="192.168.1.0/24" \
     ./zig-out/bin/vpnclient --config config.json
```
Custom routes with include/exclude rules.

---

## 📝 Environment Variables

| Variable | Values | Description |
|----------|--------|-------------|
| `VPN_SEND_ALL_TRAFFIC` | `1` or `0` | Enable full tunnel mode |
| `VPN_SERVER_HOSTNAME` | hostname | VPN server hostname (for route protection) |
| `VPN_ADVANCED_ROUTING` | `1` or `0` | Enable advanced routing rules |
| `VPN_IPV4_INCLUDE` | CIDRs | IPv4 routes to send through VPN (comma-separated) |
| `VPN_IPV4_EXCLUDE` | CIDRs | IPv4 routes to bypass VPN (comma-separated) |
| `VPN_IPV6_ENABLED` | `1` or `0` | Enable IPv6 routing |
| `VPN_IPV6_INCLUDE` | CIDRs | IPv6 routes to send through VPN |
| `VPN_IPV6_EXCLUDE` | CIDRs | IPv6 routes to bypass VPN |

---

## 🔧 Config.json Structure

```json
{
  "routing": {
    "send_all_traffic": false,
    "advanced": {
      "enabled": false,
      "ipv4": {
        "enabled": true,
        "include": ["10.0.0.0/8", "192.168.0.0/16"],
        "exclude": ["192.168.1.0/24"]
      },
      "ipv6": {
        "enabled": false,
        "include": ["2001:db8::/32"],
        "exclude": ["fe80::/10"]
      }
    }
  }
}
```

---

## 📊 Routing Modes Comparison

| Feature | Split Tunnel | Full Tunnel (Default) | Advanced |
|---------|-------------|-------------|----------|
| VPN network | ✅ VPN | ✅ VPN | ✅ Configurable |
| Internet | ❌ Direct | ✅ VPN | ✅ Configurable |
| Local network | ✅ Direct | ❌ VPN | ✅ Configurable |
| IPv6 support | ✅ | ✅ | ✅ |
| Complexity | Low | Low | High |
| Flexibility | Low | Low | Very High |

---

## 💡 Common Use Cases

### Remote Work (Corporate VPN)
Route only corporate networks through VPN:
```bash
VPN_ADVANCED_ROUTING=1 \
VPN_IPV4_INCLUDE="10.0.0.0/8,172.16.0.0/12" \
VPN_IPV4_EXCLUDE="192.168.1.0/24"
```

### Public WiFi Security
Route all traffic for maximum security:
```bash
VPN_SEND_ALL_TRAFFIC=1 \
VPN_SERVER_HOSTNAME=vpn.example.com
```

### Gaming + VPN Access
Keep local network fast, route specific game servers through VPN:
```bash
VPN_ADVANCED_ROUTING=1 \
VPN_IPV4_INCLUDE="203.0.113.0/24" \
VPN_IPV4_EXCLUDE="192.168.0.0/16"
```

### Streaming + Corporate Access
Exclude video CDNs, include corporate networks:
```bash
VPN_SEND_ALL_TRAFFIC=1 \
VPN_ADVANCED_ROUTING=1 \
VPN_IPV4_EXCLUDE="23.246.0.0/18,108.175.32.0/20" \
VPN_SERVER_HOSTNAME=vpn.example.com
```

---

## 🔍 Verification Commands

```bash
# Check routing table
netstat -rn

# Check default gateway
netstat -rn | grep "^default"

# Test VPN latency
ping 10.21.0.1

# Test internet latency
ping 1.1.1.1

# Trace route to see path
traceroute 8.8.8.8

# Check DNS resolution
dig google.com
```

---

## ⚠️ Important Notes

1. **Always run with `sudo`** - Route changes require root privileges
2. **Full tunnel is default** - All traffic routes through VPN unless disabled
3. **VPN server protection** - Full tunnel mode automatically protects VPN connection
4. **CIDR notation required** - Use `10.0.0.0/8`, not `10.0.0.0`
5. **Single IP addresses** - Use `/32` for IPv4, `/128` for IPv6
6. **Max 64 routes** - Per category (include/exclude × IPv4/IPv6)
7. **Environment > Config** - Environment variables override config.json

---

## 🛠️ Troubleshooting Quick Fixes

### Lost VPN Connection
```bash
# Restart with proper server hostname
sudo VPN_SEND_ALL_TRAFFIC=1 \
     VPN_SERVER_HOSTNAME=vpn.example.com \
     ./zig-out/bin/vpnclient --config config.json
```

### Can't Access Local Network
```bash
# Exclude local network
sudo VPN_ADVANCED_ROUTING=1 \
     VPN_IPV4_EXCLUDE="192.168.1.0/24" \
     VPN_SEND_ALL_TRAFFIC=1 \
     VPN_SERVER_HOSTNAME=vpn.example.com \
     ./zig-out/bin/vpnclient --config config.json
```

### Routes Not Applied
```bash
# Delete conflicting routes first
sudo route delete -net 10.0.0.0/8
sudo route delete default

# Then start VPN
sudo ./zig-out/bin/vpnclient --config config.json
```

---

## 📚 More Information

See [ROUTING_CONFIG.md](ROUTING_CONFIG.md) for detailed documentation.
