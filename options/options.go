package options

import (
	// "fmt"
	"log"
	"net"
	// "strings"
	"encoding/binary"

	"github.com/google/gopacket/layers"

	c "gdhcp/config"
)

type DHCPOptionValue interface {
	ToBytes() []byte
}

type IPAddress string
func (ip IPAddress) ToBytes() []byte {
	str := string(ip)
	return net.ParseIP(str).To4()
}

type IPAddressSlice []string
func (ipSlice IPAddressSlice) ToBytes() []byte {
	if len(ipSlice) == 0 {
		return nil
	}

	buf := []byte{}
	for _, ip := range ipSlice {
		parsedIP := net.ParseIP(ip).To4()
		if parsedIP != nil {
			buf = append(buf, parsedIP...)
		}
	}
	return buf
}

type Int32 uint32
func (Int Int32) ToBytes() []byte {
	// Cast Int to Uint
	Uint := uint32(Int)
	// Make 4 byte slice, since uint32 is 4 bytes
	buf := make([]byte, 4)
	// Networks use Big endian
	binary.BigEndian.PutUint32(buf, Uint)

	return buf
}

type Int16 uint16
func (Int Int16) ToBytes() []byte {
	// Cast Int to Uint
	Uint := uint16(Int)
	// Make 4 byte slice, since uint32 is 4 bytes
	buf := make([]byte, 2)
	// Networks use Big endian
	binary.BigEndian.PutUint16(buf, Uint)

	return buf
}

type Bool bool
func (b Bool) ToBytes() []byte {
	if b {
		return []byte{1}
	}
	return []byte{0}
}

type String string
func (str String) ToBytes() []byte {
	return []byte(str)
}

type ClasslessStaticRoute []byte
func (c ClasslessStaticRoute) ToBytes() []byte {
	return c
}


func GetClasslessSR(config c.Config) (DHCPOptionValue, error) {
    // Parse the CIDR to get the IP and subnet mask
    _, ipNet, err := net.ParseCIDR(config.DHCP.NetworkAddr)
    if err != nil {
        return nil, fmt.Errorf("Error parsing CIDR: %v", err)
    }

    // Determine the prefix length
    prefixLen, _ := ipNet.Mask.Size()

    // Create the option byte slice
    var option []byte
    option = append(option, byte(prefixLen))              // Prefix length
    option = append(option, ipNet.IP[0:prefixLen/8]...)   // Destination IP according to the prefix length
    option = append(option, net.ParseIP(routerIP)...)

    return ClasslessStaticRoute(option)
}

func CreateOptionMap(config c.Config) (map[layers.DHCPOpt]DHCPOptionValue) {
	return map[layers.DHCPOpt]DHCPOptionValue{
		layers.DHCPOptSubnetMask: 		IPAddress(config.DHCP.SubnetMask),
		layers.DHCPOptBroadcastAddr: 	IPAddress(config.DHCP.BroadcastAddr),

		layers.DHCPOptRouter: 			IPAddressSlice(config.DHCP.Router),
		layers.DHCPOptNameServer: 		IPAddressSlice(config.DHCP.NameServer),
		layers.DHCPOptDNS: 				IPAddressSlice(config.DHCP.DNSServer),
		layers.DHCPOptLogServer: 		IPAddressSlice(config.DHCP.LogServer),
		layers.DHCPOptNTPServers: 		IPAddressSlice(config.DHCP.NTPServer),

		layers.DHCPOptLeaseTime: 		Int32(config.DHCP.LeaseLen),
		layers.DHCPOptDatagramMTU: 		Int32(config.DHCP.DatagramMTU),
		layers.DHCPOptDefaultTTL: 		Int16(config.DHCP.DefaultTTL),
		layers.DHCPOptTCPTTL: 			Int16(config.DHCP.TCPTTL),

		layers.DHCPOptDomainName: 		String(config.DHCP.DomainName),
		layers.DHCPOptDomainSearch:		String(config.DHCP.DomainName),

		layers.DHCPOptIPForwarding: 	Bool(config.DHCP.IPForwarding),
		layers.DHCPOptRouterDiscovery: 	Bool(config.DHCP.RouterDiscovery),

		layers.DHCPOptClasslessStaticRoute: GetClasslessSR(config),
	}
}