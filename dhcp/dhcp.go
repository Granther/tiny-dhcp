package dhcp

import (
	"log"
	"net"


	"github.com/google/gopacket/layers"
	// "github.com/google/gopacket"
	
	// c "gdhcp/config"
)

func GetDHCPOption(options layers.DHCPOptions, optType layers.DHCPOpt) (layers.DHCPOption, bool) {
	var opt layers.DHCPOption

	for _, option := range options {
		if option.Type == optType {
			return option, true
		}
	}
	return opt, false
}

func GetMessageTypeOption(options layers.DHCPOptions) (layers.DHCPMsgType, bool) {
	opt, found := GetDHCPOption(options, layers.DHCPOptMessageType)

	// If the MessageType option is valid, try to convert 
	if found && len(opt.Data) > 0 {
		return layers.DHCPMsgType(opt.Data[0]), true
	}
	return layers.DHCPMsgTypeUnspecified, false
}

func GetInterfaceIP(interfaceName string) (net.IP, error) {
	var ip net.IP

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		log.Fatalf("Failed to get interface: %v", err)
		return ip, err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		log.Fatalf("Failed to get addresses from interface: %v", err)
		return ip, err
	}

	// Use the first IP address the interface hasw
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if ok && ipNet.IP.To4() != nil {
			ip = ipNet.IP
			break
		}
	}

	if ip == nil {
		log.Fatal("No valid IPv4 address found on interface: %v", interfaceName)
	}

	return ip, nil
}

func GetInterfaceHA(interfaceName string) (net.HardwareAddr, error) {
	var hardwareAddr net.HardwareAddr

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		log.Fatalf("Failed to get interface: %v", err)
		return hardwareAddr, err
	}

	hardwareAddr = iface.HardwareAddr

	return hardwareAddr, nil
}

// func JsonIPListToBytes(jsonList []string) []bytes {
// 	var byteSlice []byte 

// 	for ip := range jsonList {
// 		byteSlice = append(byteSlice, net.ParseIP(ip).To4())
// 	}

// 	return byteSlice
// }