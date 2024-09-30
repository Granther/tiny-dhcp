package options

import (
	// "log"
	// "fmt"
	"net"
	// "strings"
	"encoding/binary"

	"github.com/google/gopacket/layers"

	c "gdhcp/config"
)

// func IpToBytes(IP string) []byte {
// 	return net.ParseIP(IP).To4()
// }

// func BoolToBytes(Bool bool) []byte {
// 	if Bool {
// 		return []byte{1}
// 	}
// 	return []byte{0}
// }

// func StringToBytes(Str string) []byte {
// 	return []byte(Str)
// }

// func IntTo32Bytes(Int int) []byte {
// 	// Cast Int to Uint
// 	Uint := uint32(Int)
// 	// Make 4 byte slice, since uint32 is 4 bytes
// 	buf := make([]byte, 4)
// 	// Networks use Big endian
// 	binary.BigEndian.PutUint32(buf, Uint)

// 	return buf
// }

// func IntTo16Bytes(Int int) []byte {
// 	// Cast Int to Uint
// 	Uint := uint16(Int)
// 	// Make 4 byte slice, since uint16 is 2 bytes
// 	buf := make([]byte, 2)
// 	// Networks use Big endian
// 	binary.BigEndian.PutUint16(buf, Uint)

// 	return buf
// }

// func IpSliceToBytes(IpList []string) []byte {
// 	// We can be better and get len from IpList

//     return []byte(strings.Join(IpList, ""))
// 	// var buffer bytes.Buffer
//     // for _, s := range IpList {
//     //     buffer.WriteString(s)
//     // }
//     // return buffer.Bytes()
// 	// var totalLen int
//     // for _, s := range IpList {
//     //     totalLen += len(s)
//     // }

//     // result := make([]byte, totalLen)
//     // var i int
//     // for _, s := range IpList {
//     //     i += copy(result[i:], s)
//     // }

//     // return result
// }

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

// func GetClasslessSR(config c.Config)  {
// 	return nil
// }

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

		layers.DHCPOptHostname: 		String(config.DHCP.Hostname),
		layers.DHCPOptDomainName: 		String(config.DHCP.DomainName),

		layers.DHCPOptIPForwarding: 	Bool(config.DHCP.IPForwarding),
		layers.DHCPOptRouterDiscovery: 	Bool(config.DHCP.RouterDiscovery),

		// layers.DHCPOptClasslessStaticRoute: GetClasslessSR(config),
	}
}