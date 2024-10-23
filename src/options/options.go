package options

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"

	"github.com/google/gopacket/layers"

	"gdhcp/config"
)

// Options handler impl only has to impl CreateOptionsMap
type OptionsHandler interface {
	CreateOptionMap() map[layers.DHCPOpt]DHCPOptionValue
}

type OptionsManager struct {
	config *config.Config
}

func NewOptionsManager(config *config.Config) OptionsHandler {
	return &OptionsManager{
		config: config,
	}
}

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
	Uint := uint32(Int)
	buf := make([]byte, 4)
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

func (o *OptionsManager) GetClasslessSR() DHCPOptionValue {
	// Parse the CIDR to get the IP and subnet mask
	_, ipNet, err := net.ParseCIDR(o.config.DHCP.NetworkAddr)
	if err != nil {
		slog.Error(fmt.Sprintf("Error parsing CIDR for building SR: %v", err))
		return nil
	}

	// Determine the prefix length
	prefixLen, _ := ipNet.Mask.Size()
	routerIP := net.ParseIP(o.config.DHCP.Router)

	// Create the option byte slice
	var option []byte
	option = append(option, byte(prefixLen))            // Prefix length
	option = append(option, ipNet.IP[0:prefixLen/8]...) // Destination IP according to the prefix length
	option = append(option, routerIP...)

	return ClasslessStaticRoute(option)
}

func (o *OptionsManager) CreateOptionMap() map[layers.DHCPOpt]DHCPOptionValue {
	return map[layers.DHCPOpt]DHCPOptionValue{
		layers.DHCPOptSubnetMask:    IPAddress(o.config.DHCP.SubnetMask),
		layers.DHCPOptBroadcastAddr: IPAddress(o.config.DHCP.BroadcastAddr),
		layers.DHCPOptRouter:        IPAddress(o.config.DHCP.Router),

		layers.DHCPOptNameServer: IPAddressSlice(o.config.DHCP.NameServer),
		layers.DHCPOptDNS:        IPAddressSlice(o.config.DHCP.DNSServer),
		layers.DHCPOptLogServer:  IPAddressSlice(o.config.DHCP.LogServer),
		layers.DHCPOptNTPServers: IPAddressSlice(o.config.DHCP.NTPServer),

		layers.DHCPOptLeaseTime:   Int32(o.config.DHCP.LeaseLen),
		layers.DHCPOptDatagramMTU: Int32(o.config.DHCP.DatagramMTU),
		layers.DHCPOptDefaultTTL:  Int16(o.config.DHCP.DefaultTTL),
		layers.DHCPOptTCPTTL:      Int16(o.config.DHCP.TCPTTL),

		layers.DHCPOptDomainName: String(o.config.DHCP.DomainName),
		// layers.DHCPOptDomainSearch:		String(config.DHCP.DomainName),

		layers.DHCPOptIPForwarding:    Bool(o.config.DHCP.IPForwarding),
		layers.DHCPOptRouterDiscovery: Bool(o.config.DHCP.RouterDiscovery),

		// layers.DHCPOptClasslessStaticRoute: GetClasslessSR(config),
	}
}
