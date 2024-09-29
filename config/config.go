package config

// Configurations exported
type Configurations struct {
	Metal		MetalConfigurations
	Server		ServerConfigurations
}

type MetalConfigurations struct {
	Port			int
	ListenAddr		string
	Interface		string
	HardwareAddr	string
}

type ServerConfigurations struct {
	Subnet		string
	Gateway		string
	DNS			string
	LeaseLen	int
	IPRange		string
	ServerAddr	string
}

type Config struct {
	Server struct {
		Port 			int `json:"port"`
		ListenInterface	string `json:"listen_interface"`
		NumWorkers		int	`json:"num_workers"`
	}
	DHCP struct {

	}
}

DHCPOptSubnetMask            DHCPOpt = 1   // 4, net.IP
DHCPOptRouter                DHCPOpt = 3   // n*4, [n]net.IP
DHCPOptTimeServer            DHCPOpt = 4   // n*4, [n]net.IP
DHCPOptNameServer            DHCPOpt = 5   // n*4, [n]net.IP
DHCPOptDNS                   DHCPOpt = 6   // n*4, [n]net.IP
DHCPOptLogServer             DHCPOpt = 7   // n*4, [n]net.IP
DHCPOptHostname              DHCPOpt = 12  // n, string
DHCPOptDomainName            DHCPOpt = 15  // n, string
DHCPOptIPForwarding          DHCPOpt = 19  // 1, bool
DHCPOptDatagramMTU           DHCPOpt = 22  // 2, uint16
DHCPOptDefaultTTL            DHCPOpt = 23  // 1, byte
DHCPOptInterfaceMTU          DHCPOpt = 26  // 2, uint16
DHCPOptBroadcastAddr         DHCPOpt = 28  // 4, net.IP
DHCPOptRouterDiscovery       DHCPOpt = 31  // 1, bool
DHCPOptStaticRoute           DHCPOpt = 33  // n*8, [n]{net.IP/net.IP} -- note the 2nd is router not mask
DHCPOptTCPTTL                DHCPOpt = 37  // 1, byte
DHCPOptNISDomain             DHCPOpt = 40  // n, string
DHCPOptNISServers            DHCPOpt = 41  // 4*n,  [n]net.IP
DHCPOptNTPServers            DHCPOpt = 42  // 4*n, [n]net.IP
DHCPOptVendorOption          DHCPOpt = 43  // n, [n]byte // may be encapsulated.
DHCPOptRequestIP             DHCPOpt = 50  // 4, net.IP
DHCPOptLeaseTime             DHCPOpt = 51  // 4, uint32
DHCPOptExtOptions            DHCPOpt = 52  // 1, 1/2/3
DHCPOptMessageType           DHCPOpt = 53  // 1, 1-7
DHCPOptServerID              DHCPOpt = 54  // 4, net.IP
DHCPOptParamsRequest         DHCPOpt = 55  // n, []byte
DHCPOptMessage               DHCPOpt = 56  // n, 3
DHCPOptMaxMessageSize        DHCPOpt = 57  // 2, uint16
DHCPOptT1                    DHCPOpt = 58  // 4, uint32
// Figure 3-8 Renewing an IP address lease. When the lease reaches 50% (T1) of its validity period, the DHCP client unicasts a DHCP Request message to the DHCP server to request lease renewal. If the server renews the lease (counted from 0), it sends a DHCP ACK message to the client.
DHCPOptT2                    DHCPOpt = 59  // 4, uint32
DHCPOptClassID               DHCPOpt = 60  // n, []byte
DHCPOptClientID              DHCPOpt = 61  // n >=  2, []byte
DHCPOptDomainSearch          DHCPOpt = 119 // n, string
DHCPOptClasslessStaticRoute  DHCPOpt = 121 //
