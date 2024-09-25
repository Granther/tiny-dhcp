package main

import (
	"net"
	"fmt"
	"log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	c "gdhcp/config"
	"github.com/spf13/viper"
)

type DHCPPacket struct {
	Op 		byte		// Operation
	HType 	byte		//
	HLen 	byte 		// Mac addr len
	HOps	byte		//
	XId		byte		// Transaction id
    Secs  uint16    	// Seconds elapsed
    Flags uint16    	// Flags
    CIAddr net.IP   	// Client IP Address
    YIAddr net.IP   	// Your (client) IP Address
    SIAddr net.IP   	// Server IP Address
    GIAddr net.IP   	// Gateway IP Address
    CHAddr [16]byte 	// Client hardware address
    SName  [64]byte 	// Optional server host name
    File   [128]byte 	// Boot file name
    Options []byte  	// DHCP options
}

// UDP port for DHCP Server
const DHCPServerPort = 67
const BufferSize = 1024

func main() {
	config, err := readConfig(); if err != nil {
		// %v is value in its default format (hope its printable)
		log.Fatalf("Error parsing config file: %v", err)
	}

	fmt.Printf(config.Server.DNS)

	var ip net.IP
	interfaceName := config.Metal.Interface
	hardwareAddr, err := net.ParseMAC(config.Metal.HardwareAddr)
	fmt.Printf(config.Metal.HardwareAddr)

	if interfaceName == "any" {
		ip = net.IPv4zero
	} else if interfaceName != "any" {
		addr, err := getInterfaceIP(interfaceName); if err != nil {
			log.Fatalf("Error occured when getting the IP for interface")
		}
		ip = addr
	}

	// ha, err := getInterfaceHA(interfaceName)
	fmt.Printf(hardwareAddr.String())

    // Listen for incoming UDP packets on port 67 on this addr
    addr := net.UDPAddr{
        Port: DHCPServerPort,
        IP:   ip,
    }
    
    conn, err := net.ListenUDP("udp", &addr)
    if err != nil {
        log.Fatalf("Error listening on UDP port %d: %v", DHCPServerPort, err)
    }

	// Close the connection upon exit even though its an endless loop
    defer conn.Close()
    
    // Start main loop to receive packets
    for {
        // Buffer to hold incoming packet
        buffer := make([]byte, BufferSize)
        
        // Receive the UDP packet
        n, clientAddr, err := conn.ReadFromUDP(buffer)
        if err != nil {
            log.Printf("Error receiving packet: %v", err)
            continue
        }
        
        // Start goroutine to handle the packet
        go handleDHCPPacket(buffer[:n], clientAddr, config)
    }
}

func getInterfaceIP(interfaceName string) (net.IP, error) {
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

func getInterfaceHA(interfaceName string) (net.HardwareAddr, error) {
	var hardwareAddr net.HardwareAddr

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		log.Fatalf("Failed to get interface: %v", err)
		return hardwareAddr, err
	}

	hardwareAddr = iface.HardwareAddr

	return hardwareAddr, nil
}

func readConfig() (c.Configurations, error) {
	viper.SetConfigName("config")
	viper.AddConfigPath(".")

	// viper.AutomaticEnv()

	viper.SetConfigType("yml")
	var config c.Configurations

	if err := viper.ReadInConfig(); err != nil {
		return config, fmt.Errorf("Error reading config file, %s", err)
	}
	
	// // Set undefined variables
	// viper.SetDefault("database.dbname", "test_db")

	err := viper.Unmarshal(&config)
	if err != nil {
		return config, fmt.Errorf("Error decoding from struct, %s", err)
	}

	return config, nil
}

// Function to handle a DHCP packet in a new goroutine
func handleDHCPPacket(packet_slice []byte, clientAddr *net.UDPAddr, config c.Configurations) {
	dhcp_packet := gopacket.NewPacket(packet_slice, layers.LayerTypeDHCPv4, gopacket.Default)
	dhcp_layer := dhcp_packet.Layer(layers.LayerTypeDHCPv4)

	// If nil, essentially drop the packet
	if dhcp_packet == nil || dhcp_layer == nil{
		log.Printf("Error, unable to get DHCP packet or layer")
		return
	}

	dhcp, _ := dhcp_layer.(*layers.DHCPv4)

	// Bootp operation, above DHCP Options
	switch dhcp.Operation {
	case layers.DHCPOpRequest:
		log.Printf("Bootp packet is Request")
	case layers.DHCPOpReply:
		log.Printf("Bootp packet is Reply")
	default:
		log.Printf("Error, no Operation specified, I should be confused")
	}

	// message, found := getDHCPOption(dhcp.Options, layers.DHCPOptMessageType)

	switch message, _ := getMessageTypeOption(dhcp.Options); message {
	case layers.DHCPMsgTypeDiscover:
		log.Printf("Got Discover")
		sendOffer(packet_slice, config)
	case layers.DHCPMsgTypeRequest:
		log.Printf("Got Request")
	case layers.DHCPMsgTypeOffer:
		log.Printf("Got Offer")
	case layers.DHCPMsgTypeDecline:
		log.Printf("Got Decline")
	case layers.DHCPMsgTypeAck:
		log.Printf("Got Ack")
	case layers.DHCPMsgTypeNak:
		log.Printf("Got Nak")
	case layers.DHCPMsgTypeRelease:
		log.Printf("Got Release")
	case layers.DHCPMsgTypeInform:
		log.Printf("Got Inform")
	case layers.DHCPMsgTypeUnspecified:
		log.Printf("Error, DHCP operation type is unspecified")
	}
}

// Get specific option from DHCP options since it is byte slice
func getDHCPOption(options layers.DHCPOptions, optType layers.DHCPOpt) (*layers.DHCPOption, bool) {
	for _, option := range options {
		if option.Type == optType {
			return &option, true
		}
	}
	return nil, false
}

func getMessageTypeOption(options layers.DHCPOptions) (layers.DHCPMsgType, bool) {
	opt, found := getDHCPOption(options, layers.DHCPOptMessageType)

	// If the MessageType option is valid, try to convert 
	if found && len(opt.Data) > 0 {
		return layers.DHCPMsgType(opt.Data[0]), true
	}
	return layers.DHCPMsgTypeUnspecified, false
}

func generateAddr() (net.IP) {
	return net.IP{192, 168, 1, 180}
}

func sendOffer(packet_slice []byte, config c.Configurations) {
	// DHCPMsgTypeOffer
	// DHCPOpReply
	// DHCPOptSubnetMask
	// DHCPOptRouter
	// DHCPOptDNS
	// DHCPOptDomainName
	// DHCPOptBroadcastAddr
	// DHCPOptLeaseTime
	// DHCPOptMessageType

	dhcp_packet := gopacket.NewPacket(packet_slice, layers.LayerTypeEthernet, gopacket.Default)
    ethLayer := dhcp_packet.Layer(layers.LayerTypeEthernet)

	// var srcHardwareAddr net.HardwareAddr 

	ethernetPacket, _ := ethLayer.(*layers.Ethernet)
	// srcHardwareAddr := ethernetPacket.SrcMAC

	offeredIP := generateAddr()

	ipLayer := &layers.IPv4{
		SrcIP: net.IP{0, 0, 0, 0},
		DstIP: offeredIP,
	}

	fmt.Println(config.Metal.HardwareAddr)

	srcMac, err := net.ParseMAC(config.Metal.HardwareAddr)
	if err != nil {
		log.Fatalf("Error occured while parsing server Hardware addr")
	}

	ethernetLayer := &layers.Ethernet{
        SrcMAC: srcMac,
		DstMAC: ethernetPacket.SrcMAC,
    }

	udpLayer := &layers.UDP{
        SrcPort: layers.UDPPort(67),
        DstPort: layers.UDPPort(68),
    }

	msgTypeOption := layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeOffer)})

    // Collect them into a DHCPOptions slice
    dhcpOptions := layers.DHCPOptions{
        msgTypeOption,
    }
	dhcpLayer, _ := constructOfferLayer(packet_slice, offeredIP, dhcpOptions, config) // Returns pointer to what was affected

	options := gopacket.SerializeOptions{}
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options, 
		ipLayer,
		ethernetLayer,
		udpLayer,
		dhcpLayer,
	)
	outgoingPacket := buffer.Bytes()

	// Just for windows debugging, get all devices and use the first one
	devices, _ := pcap.FindAllDevs()
	for _, device := range devices {
		fmt.Println(device.Name)
		fmt.Println(device.Description)
	}

	// Windows interface \\Device\\NPF_{3C62326A-1389-4DB7-BCF8-55747D0B8757}
	// Linux interface enp0s31f6

	handle, err := pcap.OpenLive("enp0s31f6", 67, true, pcap.BlockForever)

	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	err = handle.WritePacketData(outgoingPacket)
    if err != nil {
        log.Fatal(err)
    }
}

func constructOfferLayer(packet_slice []byte, offeredIP net.IP, DHCPOptions layers.DHCPOptions, config c.Configurations) (*layers.DHCPv4, error) {
	DHCPPacket := gopacket.NewPacket(packet_slice, layers.LayerTypeDHCPv4, gopacket.Default)
	EthernetPacket := gopacket.NewPacket(packet_slice, layers.LayerTypeEthernet, gopacket.Default)

	discDhcpLayer := DHCPPacket.Layer(layers.LayerTypeDHCPv4)
	discEthLayer := EthernetPacket.Layer(layers.LayerTypeEthernet)

	lowPacket, ok := discDhcpLayer.(*layers.DHCPv4)
	if !ok {
		log.Fatalf("Error while parsing DHCPv4 layer in packet")
	} 

	ethernetPacket, ok := discEthLayer.(*layers.Ethernet)
	if !ok {
		log.Fatalf("Error while parsing Ethernet layer in packet")
	} 

	var hardwareLen uint8 = 6
	var hardwareOpts uint8 = 0
	xid := lowPacket.Xid
	secs := lowPacket.Secs

	dhcpLayer := &layers.DHCPv4{
		Operation:    layers.DHCPOpReply, // Type of Bootp reply
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  hardwareLen,
		HardwareOpts: hardwareOpts,
		Xid:          xid, // Need this from discover
		Secs:         secs, // Make this up for now
		YourClientIP: offeredIP, 
		ClientHWAddr: ethernetPacket.SrcMAC,
		Options:     DHCPOptions,
	}

	// Operation:    layers.DHCPOpReply // Type of Bootp reply
	// HardwareType: layers.LinkTypeEthernet
	// HardwareLen  uint8
	// HardwareOpts uint8
	// Xid          uint32 // Need this from discover
	// Secs         uint16 // Make this up for now
	// Flags        uint16 // Think I can leave this nil
	// ClientIP     net.IP // Gonna leave blank proabably, its not assigned yet
	// YourClientIP net.IP 
	// ClientHWAddr net.HardwareAddr
	// Options      DHCPOptions

	return dhcpLayer, nil
}