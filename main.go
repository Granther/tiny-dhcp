package main

import (
	"net"
	"fmt"
	"log"
	"github.com/google/gopacket"
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

    // Listen for incoming UDP packets on port 67
    addr := net.UDPAddr{
        Port: DHCPServerPort,
        IP:   net.IPv4zero,
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
        go handleDHCPPacket(buffer[:n], clientAddr)
    }
}

func getInterfaceIP(interface string) (ip net.IP, error) {
	iface, err := net.InterfaceByName(interface)
	if err != nil {
		log.Fatalf("Failed to get interface: %v", err)
	}

	addr, err := iface.Addrs()
	if err != nil {
		log.Fatalf("Failed to get addresses from interface: %v", err)
	}

	// Use the first IP address the interface hasw
	var ip net.IP
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
func handleDHCPPacket(packet_slice []byte, clientAddr *net.UDPAddr) {
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

