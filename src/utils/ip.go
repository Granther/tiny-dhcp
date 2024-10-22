package utils

import (
	"fmt"
	"net"
)

// Return first IP bound to passed interface
func GetInterfaceIP(ifaceName string) (net.IP, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s by name: %w", ifaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses bound to interface %s: %w", ifaceName, err)
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
		return nil, fmt.Errorf("no valid ipv4 address found on interface %s", ifaceName)
	}

	return ip, nil
}

// Return hardware address associated with interface
func GetInterfaceHA(ifaceName string) (net.HardwareAddr, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s by name: %w", ifaceName, err)
	}

	hardwareAddr := iface.HardwareAddr
	if hardwareAddr == nil {
		return nil, fmt.Errorf("iface %s does not have a hardware address", ifaceName)
	}

	return hardwareAddr, nil
}
