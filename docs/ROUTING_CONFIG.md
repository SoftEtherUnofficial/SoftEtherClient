# VPN Routing Configuration Guide

This document explains how to configure VPN routing behavior using the new config-based system.

## Overview

The VPN client now supports three routing modes:

1. **Split Tunnel** - Only VPN network traffic goes through the tunnel
2. **Full Tunnel** (default) - ALL traffic routes through VPN
3. **Advanced Routing** - Custom include/exclude rules with IPv4/IPv6 support

## Configuration Methods

### 1. Using config.json (Recommended)

Edit `config.json` to include the `routing` section:

```json
{
  "server": "vpn.example.com",
  "port": 443,
  "hub": "VPN",
  "username": "<username>",
  "password_hash": "<hashed_password>",
  "use_compress": true,
  "performance": {
    "profile": "<latency|balanced|throughput>"
  },
  "routing": {
    "send_all_traffic": true,
    "advanced": {
      "enabled": false,
      "ipv4": {
        "enabled": false,
        "include": [],
        "exclude": []
      },
      "ipv6": {
        "enabled": false,
        "include": [],
        "exclude": []
      }
    }
  }
}
```

### 2. Using Environment Variables

Environment variables override config.json settings:

```bash
# Enable full tunnel mode
```bash
export VPN_SEND_ALL_TRAFFIC=1
export VPN_SERVER_HOSTNAME=vpn.example.com

# Run VPN client
sudo ./zig-out/bin/vpnclient --config config.json
```

## Routing Modes

### Split Tunnel

Only VPN network traffic goes through the tunnel. Internet traffic uses your normal connection.

**Config:**
```json
{
  "routing": {
    "send_all_traffic": false,
    "advanced": {
      "enabled": false
    }
  }
}
```

**Environment:**
```bash
# No environment variables needed (default behavior)
sudo ./zig-out/bin/vpnclient --config config.json
```

**Use Cases:**
- Local network access required
- Testing VPN connectivity
- Accessing VPN resources without affecting internet speed

---

### Full Tunnel (Default)

ALL traffic (including internet) routes through VPN.

**Config:**
```json
{
  "routing": {
    "send_all_traffic": true,
    "advanced": {
      "enabled": false
    }
  }
}
```

**Environment:**
```bash
export VPN_SEND_ALL_TRAFFIC=1
export VPN_SERVER_HOSTNAME=vpn.example.com 
sudo ./zig-out/bin/vpnclient --config config.json
```

**Features:**
- Protects VPN server connection (adds host route through original gateway)
- Replaces default route to point to VPN gateway
- All traffic encrypted through VPN

**Use Cases:**
- Maximum privacy
- Public WiFi security
- Bypassing regional restrictions
- Corporate security policies

---

### Advanced Routing

Custom include/exclude rules with CIDR notation for fine-grained control.

**Config:**
```json
{
  "routing": {
    "send_all_traffic": false,
    "advanced": {
      "enabled": true,
      "ipv4": {
        "enabled": true,
        "include": [
          "10.0.0.0/8",
          "192.168.0.0/16",
          "8.8.8.8/32"
        ],
        "exclude": [
          "192.168.1.0/24",
          "10.21.252.0/24"
        ]
      },
      "ipv6": {
        "enabled": true,
        "include": [
          "2001:db8::/32"
        ],
        "exclude": [
          "fe80::/10"
        ]
      }
    }
  }
}
```

**Environment:**
```bash
# Enable advanced routing
export VPN_ADVANCED_ROUTING=1

# IPv4 routes
export VPN_IPV4_INCLUDE="10.0.0.0/8,192.168.0.0/16,8.8.8.8/32"
export VPN_IPV4_EXCLUDE="192.168.1.0/24,10.21.252.0/24"

# IPv6 routes (optional)
export VPN_IPV6_ENABLED=1
export VPN_IPV6_INCLUDE="2001:db8::/32"
export VPN_IPV6_EXCLUDE="fe80::/10"

sudo ./zig-out/bin/vpnclient --config config.json
```

**Rules:**
- **Include routes**: Traffic to these networks goes through VPN
- **Exclude routes**: Traffic to these networks goes through original gateway
- Multiple CIDRs supported (comma-separated)
- Both IPv4 and IPv6 supported
- Max 64 routes per category (include/exclude × IPv4/IPv6)

**Use Cases:**
- Route specific corporate networks through VPN
- Exclude local network (e.g., printer, NAS)
- Split DNS (route specific DNS servers through VPN)
- Hybrid cloud setups

---

## Examples

### Example 1: Full Tunnel with Config

```json
{
  "routing": {
    "send_all_traffic": true
  }
}
```

```bash
export VPN_SERVER_HOSTNAME=vpn.example.com
sudo ./zig-out/bin/vpnclient --config config.json
```

### Example 2: Route Corporate Networks Only

```bash
export VPN_ADVANCED_ROUTING=1
export VPN_IPV4_INCLUDE="10.0.0.0/8,172.16.0.0/12,192.168.100.0/24"
export VPN_IPV4_EXCLUDE="192.168.1.0/24"  # Local network
sudo ./zig-out/bin/vpnclient --config config.json
```

### Example 3: Route DNS Through VPN

```bash
export VPN_ADVANCED_ROUTING=1
export VPN_IPV4_INCLUDE="8.8.8.8/32,8.8.4.4/32,1.1.1.1/32"  # Google & Cloudflare DNS
sudo ./zig-out/bin/vpnclient --config config.json
```

### Example 4: Exclude Video Streaming

```bash
export VPN_SEND_ALL_TRAFFIC=1
export VPN_ADVANCED_ROUTING=1
# Route all traffic through VPN except Netflix/YouTube CDN ranges
export VPN_IPV4_EXCLUDE="23.246.0.0/18,108.175.32.0/20"
export VPN_SERVER_HOSTNAME=vpn.example.com
sudo ./zig-out/bin/vpnclient --config config.json
```

---

## Verification

### Check Active Routes

```bash
# View all routes
netstat -rn

# Check default gateway
netstat -rn | grep "^default"

# Check specific network
netstat -rn | grep "10.21"
```

### Test Routing

```bash
# Test VPN network
ping 10.21.0.1

# Test internet (should go through VPN if full tunnel)
ping 1.1.1.1

# Trace route
traceroute 8.8.8.8
```

### Expected Latency

- **Split Tunnel**: 
  - VPN network: ~300ms (through VPN)
  - Internet: ~5-10ms (direct)
  
- **Full Tunnel**:
  - VPN network: ~300ms
  - Internet: ~300ms (through VPN)

---

## Troubleshooting

### VPN Server Connection Lost

If you enable full tunnel and lose VPN connection:

**Problem**: Default route changed before protecting VPN server route

**Solution**: The code now automatically:
1. Resolves VPN server hostname to IP
2. Adds protected host route for server through original gateway
3. Only then replaces default route

### Local Network Not Accessible

**Problem**: Full tunnel routes all traffic through VPN

**Solution**: Use advanced routing with exclude rules:

```bash
export VPN_ADVANCED_ROUTING=1
export VPN_IPV4_EXCLUDE="192.168.1.0/24"  # Your local network
export VPN_SEND_ALL_TRAFFIC=1
```

### Routes Not Applied

**Problem**: Permission denied or route conflicts

**Solution**:
1. Run with `sudo`
2. Check for conflicting routes: `netstat -rn`
3. Delete conflicting routes: `sudo route delete -net 10.0.0.0/8`

### DNS Not Resolving

**Problem**: DNS server not routed correctly

**Solution**: Add DNS servers to include routes:

```bash
export VPN_IPV4_INCLUDE="8.8.8.8/32,8.8.4.4/32"
```

---

## Performance Considerations

### Split Tunnel
- **Best For**: Normal browsing, local resources
- **Latency**: Direct connection for internet
- **Security**: Medium (only VPN traffic encrypted)

### Full Tunnel  
- **Best For**: Public WiFi, maximum privacy
- **Latency**: All traffic through VPN (~300ms)
- **Security**: High (all traffic encrypted)

### Advanced Routing
- **Best For**: Hybrid scenarios, corporate policies
- **Latency**: Mixed (per-network routing)
- **Security**: Configurable (per-network encryption)

---

## Configuration Priority

Environment variables > config.json > defaults

1. Check environment variables first
2. Fall back to config.json settings
3. Use defaults if nothing specified

---

## Limits

- Maximum 64 include routes per IP family (IPv4/IPv6)
- Maximum 64 exclude routes per IP family (IPv4/IPv6)
- CIDR notation required (e.g., "10.0.0.0/8", not "10.0.0.0")
- Single IP: use /32 for IPv4, /128 for IPv6

---

## Building

```bash
cd SoftEtherClient
zig build
```

---

## See Also

- [README.md](../README.md) - General VPN client documentation
- [TROUBLESHOOTING.md](../../docs/TROUBLESHOOTING.md) - Common issues and solutions
