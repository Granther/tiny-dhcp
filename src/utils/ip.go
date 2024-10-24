package utils

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/google/gopacket/layers"
)

// Return first IP bound to passed interface
func GetInterfaceIP(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses bound to interface %s: %w", iface.Name, err)
	}

	// Use the first IP address the interface has
	var ip net.IP
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if ok && ipNet.IP.To4() != nil {
			ip = ipNet.IP
			break
		}
	}

	if ip == nil {
		return nil, fmt.Errorf("no valid ipv4 address found on interface %s", iface.Name)
	}

	return ip, nil
}

// Return hardware address associated with interface
func GetInterfaceMac(iface *net.Interface) (net.HardwareAddr, error) {
	hardwareAddr := iface.HardwareAddr
	if hardwareAddr == nil {
		return nil, fmt.Errorf("iface %s does not have a hardware address", iface.Name)
	}

	return hardwareAddr, nil
}

// Returns built UDP addr using iface's IP
func GetUDPAddr(iface *net.Interface) (*net.UDPAddr, error) {
	ip, err := GetInterfaceIP(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to get ip for udp addr: %w", err)
	}

	return &net.UDPAddr{Port: 67, IP: ip}, nil
}

// Increment the last octet of the IP address
func IncrementIP(ip net.IP) net.IP {
	newIP := make(net.IP, len(ip))
	copy(newIP, ip)

	for i := len(newIP) - 1; i >= 0; i-- {
		newIP[i]++
		if newIP[i] != 0 {
			break
		}
	}
	return newIP
}

func IsIPEqual(ip1, ip2 net.IP) bool {
	return ip1.Equal(ip2)
}

func IPsContains(ips []net.IP, ip net.IP) bool {
	for _, item := range ips {
		if item.Equal(ip) {
			return true
		}
	}

	return false
}

// Fixes mac addr to be correct size if sent as locally administered, returns true if LA'd
func processMAC(mac net.HardwareAddr) (net.HardwareAddr, bool, error) {
	if len(mac) > 6 {
		slog.Debug("Mac is larger than 6 bytes, fixing...")
		mac = mac[1:]
		return mac, true, nil
	} else if len(mac) == 6 {
		slog.Debug("Mac is good")
		return mac, false, nil
	} else {
		return net.HardwareAddr{}, false, fmt.Errorf("error processing mac addr")
	}
}

func extractMAC(dhcpLayer *layers.DHCPv4) (net.HardwareAddr, error) {
	clientMAC, ok := GetDHCPOption(&dhcpLayer.Options, layers.DHCPOptClientID)
	if !ok {
		return nil, fmt.Errorf("unable to get client mac from dhcp layer")
	}

	mac, _, err := processMAC(net.HardwareAddr(clientMAC.Data))
	if err != nil {
		return nil, fmt.Errorf("error processing mac to usable form: %v", err)
	}

	return mac, nil
}

// Convert net ip to 16 byte representation
func IpTo16(ip net.IP) *[16]byte {
	var ipArr [16]byte
	copy(ipArr[:], ip.To16())
	return &ipArr
}