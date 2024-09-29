package device

// import (
// 	"log"
// 	"net"
// 	"fmt"

// 	c "gdhcp/config"
// )

// func GetUDPAddr(interName string) (*net.UDPAddr) {
// 	// If interface is any, 0.0.0.0

// 	// else
// 	// See if interface with that name exists

// 	// get interface ip
// 	// return udpaddr with port and addr

// 	if interName == "any" {
// 		log.Println("Interface is any, setting listen addr to 0.0.0.0:67")
// 		return net.UDPAddr(Port: 67, IP: net.IP{0, 0, 0, 0}), nil
// 	}

// 	devices, _ := pcap.FindAllDevs()
// 	for _, device := range devices {
// 		if interName == device.Name {
// 			ip := GetInterfaceIP()
// 			log.Println("Interface found, setting listen addr to 0.0.0.0:67")
// 		}
// 	}

// 	iface, err := net.InterfaceByName(interName)
// 	if err != nil {
// 		return nil, fmt.Errorf("Failed to get interface: %v", err)
// 	}

// 	ip, err := GetInterfaceIP(iface)
// 	if err != nil {
// 		return nil, fmt.Errorf("Failed to get interface IP: %v", err)
// 	}

// 	return &net.UDPAddr(Port: 67, IP: ip)
// }

// func GetInterfaceIP(iface net.Interface) (net.IP, error) {
// 	var ip net.IP

// 	addrs, err := iface.Addrs()
// 	if err != nil {
// 		return ip, fmt.Errorf("Failed to get addresses from interface: %w", err)
// 	}

// 	// Use the first IP address the interface has
// 	for _, addr := range addrs {
// 		ipNet, ok := addr.(*net.IPNet)
// 		if ok && ipNet.IP.To4() != nil {
// 			ip = ipNet.IP
// 			break
// 		}
// 	}

// 	if ip == nil {
// 		return ip, fmt.Errorf("No valid IPv4 address found on interface: %v", interfaceName)
// 	}

// 	return ip, nil
// }