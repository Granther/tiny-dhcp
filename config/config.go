package main

import (
	"log"
	"fmt"
	"encoding/json"
	"io/ioutil"
)

type DHCP struct {
	SubnetMask		string `json:"subnet_mask"`
	Router			[]string `json:"router"`
	TimeServer		[]string `json:"time_server"`
	NameServer		[]string `json:"name_server"`
	DNSServer		[]string `json:"dns_server"`
	LogServer		[]string `json:"log_server"`
	LeaseLen		int `json:"lease_len"`
	Hostname		string `json:"hostname"`
	DomainName		string `json:"domain_name"`
	IPForwarding	bool `json:"ip_forwarding"`
	DatagramMTU		int `json:"datagram_mtu"`
	DefaultTTL		int `json:"default_ttl"`
	TCPTTL			int `json:"tcp_ttl"`
	BroadcastAddr	string `json:"broadcase_add"`
	RouterDiscovery bool `json:"router_discovery"`
	NTPServer		[]string `json:"ntp_server"`
}

type Server struct {
	Port 			int `json:"port"`
	ListenInterface	string `json:"listen_interface"`
	NumWorkers		int	`json:"num_workers"`
}

type Config struct {
	Server Server `json:"server"`
	DHCP DHCP `json:"dhcp"`
}

// func ReadConfig(configFile string) (*Config) {

// }

func WriteConfig(writePath string, config *Config) error {
    jsonData, err := json.MarshalIndent(config, "", "    ")
    if err != nil {
        log.Fatalf("Error marshaling to JSON, %v", err)
		return err
	}

	writePath = writePath + "config.json"
	err = ioutil.WriteFile(writePath, jsonData, 0666)
	if err != nil {
		return fmt.Errorf("Error writing marshalled JSON to config file: %w", err)
	}	

	// // Output the JSON string
    // fmt.Println(string(jsonData))

	return nil
}

func GetDefaultConfig() *Config {
	return &Config{
        Server: Server{
            Port: 100,
            ListenInterface: "any",
            NumWorkers: 10,
        },
        DHCP: DHCP {
            SubnetMask: "255.255.255.0",
            Router: []string{"192.168.1.1"},
			TimeServer:		[]string{},
			NameServer:		[]string{},
			DNSServer:		[]string{},
			LogServer:		[]string{},
			LeaseLen:		30000,
			Hostname:		"gdhcp",
			DomainName:		"local",
			IPForwarding:	true,
			DatagramMTU:	1500,
			DefaultTTL:		254,
			TCPTTL:			254,     
			BroadcastAddr:	"255.255.255.255",
			RouterDiscovery: true,
			NTPServer:		[]string{},
        },
    }
}

func main() {
	config := GetDefaultConfig()
	WriteConfig("./", config)
}


// DHCPOptSubnetMask            DHCPOpt = 1   // 4, net.IP
// DHCPOptRouter                DHCPOpt = 3   // n*4, [n]net.IP
// DHCPOptTimeServer            DHCPOpt = 4   // n*4, [n]net.IP
// DHCPOptNameServer            DHCPOpt = 5   // n*4, [n]net.IP
// DHCPOptDNS                   DHCPOpt = 6   // n*4, [n]net.IP
// DHCPOptLogServer             DHCPOpt = 7   // n*4, [n]net.IP
// DHCPOptLeaseTime             DHCPOpt = 51  // 4, uint32
// DHCPOptHostname              DHCPOpt = 12  // n, string
// DHCPOptDomainName            DHCPOpt = 15  // n, string
// DHCPOptIPForwarding          DHCPOpt = 19  // 1, bool
// DHCPOptDatagramMTU           DHCPOpt = 22  // 2, uint16
// DHCPOptDefaultTTL            DHCPOpt = 23  // 1, byte
// DHCPOptTCPTTL                DHCPOpt = 37  // 1, byte
// DHCPOptBroadcastAddr         DHCPOpt = 28  // 4, net.IP
// DHCPOptRouterDiscovery       DHCPOpt = 31  // 1, bool
// DHCPOptNTPServers            DHCPOpt = 42  // 4*n, [n]net.IP

// DHCPOptVendorOption          DHCPOpt = 43  // n, [n]byte // may be encapsulated.

// DHCPOptRequestIP             DHCPOpt = 50  // 4, net.IP
// DHCPOptExtOptions            DHCPOpt = 52  // 1, 1/2/3
// DHCPOptMessageType           DHCPOpt = 53  // 1, 1-7
// DHCPOptParamsRequest         DHCPOpt = 55  // n, []byte
// DHCPOptMessage               DHCPOpt = 56  // n, 3
// // DHCPOptT1                    DHCPOpt = 58  // 4, uint32
// // // Figure 3-8 Renewing an IP address lease. When the lease reaches 50% (T1) of its validity period, the DHCP client unicasts a DHCP Request message to the DHCP server to request lease renewal. If the server renews the lease (counted from 0), it sends a DHCP ACK message to the client.
// // DHCPOptT2                    DHCPOpt = 59  // 4, uint32

// // Non config
// DHCPOptClassID               DHCPOpt = 60  // n, []byte
// DHCPOptClientID              DHCPOpt = 61  // n >=  2, []byte
// DHCPOptDomainSearch          DHCPOpt = 119 // n, string

// // Work
// DHCPOptClasslessStaticRoute  DHCPOpt = 121 //
// // DHCPOptInterfaceMTU          DHCPOpt = 26  // 2, uint16 Can get auto?
// DHCPOptServerID              DHCPOpt = 54  // 4, net.IP
// DHCPOptStaticRoute           DHCPOpt = 33  // n*8, [n]{net.IP/net.IP} -- note the 2nd is router not mask
// DHCPOptMaxMessageSize        DHCPOpt = 57  // 2, uint16 Set to interface mtu


// Configurations exported
// type Configurations struct {
// 	Metal		MetalConfigurations
// 	Server		ServerConfigurations
// }

// type MetalConfigurations struct {
// 	Port			int
// 	ListenAddr		string
// 	Interface		string
// 	HardwareAddr	string
// }

// type ServerConfigurations struct {
// 	Subnet		string
// 	Gateway		string
// 	DNS			string
// 	LeaseLen	int
// 	IPRange		string
// 	ServerAddr	string
// }