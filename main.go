package main

import (
	"net"
	"fmt"
	"log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	c "gdhcp/config"
	// dhcp "gdhcp/dhcp"
	"github.com/spf13/viper"
)

type Server struct {
	conn		*net.UDPConn
	handle		*pcap.Handle
	config		c.Configurations
	workerPool	chan struct{}
	packetch 	chan packetJob
	sendch		chan []byte
	quitch		chan struct{}
}

type packetJob struct {
    data        []byte
    clientAddr  *net.UDPAddr
}

func NewServer(config c.Configurations) (*Server, error) {
	addr := config.Metal.ListenAddr
	port := config.Metal.Port
	listenAddr := net.UDPAddr{Port: port, IP: net.ParseIP(addr)}
	
	conn, err := net.ListenUDP("udp", &listenAddr)
	if err != nil {
        return nil, fmt.Errorf("Error creating server UDP listener: %v", err)
    }

	inter := "wlp2s0"
	handle, err := pcap.OpenLive(inter, 1500, false, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("Could not open pcap device: %w", err)
	}

	numWorkers := config.Server.NumWorkers
	return &Server{
		conn:		conn,
		handle:		handle,
		config:		config,
		workerPool:	make(chan struct{}, numWorkers),
		packetch:	make(chan packetJob, 1000), // Can hold 1000 packets
		sendch:		make(chan []byte, 1000), // Can hold 1000 queued packets to be sent
		quitch:		make(chan struct{}),
	}, nil
}

func (s *Server) Start() error {
	log.Printf("Starting server...")

	numWorkers := s.config.Server.NumWorkers
	for i := 0; i < numWorkers; i++ {
		go s.worker()
	}

	go s.receivePackets()
	go s.sendPackets()

	log.Printf("Server is now listening for packets/quitch")
	// Wait for quit signal
	<-s.quitch

	// Close connection and channels
	s.conn.Close()
	s.handle.Close()
	close(s.packetch)
	close(s.workerPool)
	close(s.sendch)
	
	return nil
}

func (s *Server) receivePackets() {
    for {
        buffer := make([]byte, 4096)
        n, clientAddr, err := s.conn.ReadFromUDP(buffer)
        if err != nil {
            log.Printf("Error receiving packet: %v", err)
            continue
        }
        
        select {
        case s.packetch <- packetJob{data: buffer[:n], clientAddr: clientAddr}:
            // Packet added to queue
        default:
            // Queue is full, log and drop packet
            log.Printf("Packet queue full, dropping packet from %v", clientAddr)
        }
    }
}

func (s *Server) sendPackets() {
	// Iterate over sendchannel, send all ready packets
	for packet := range s.sendch {
		err := s.sendPacket(packet)
		if err != nil {
			log.Fatalf("Error occured while sending ready packet: %v", err)
		}
	}
}

func (s *Server) sendPacket(packet []byte) error {
	if err := s.handle.WritePacketData(packet); err != nil {
		return fmt.Errorf("Failed to send packet: %w", err)
	}
	fmt.Println("Send packet from sendPacket")
	return nil
}

func (s *Server) worker() {
    for job := range s.packetch {
        s.workerPool <- struct{}{} 
        s.handleDHCPPacket(job.data, job.clientAddr, s.config)
        <-s.workerPool
    }
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

func main() {
	config, err := readConfig(); if err != nil {
		log.Fatalf("Error parsing config file: %v", err)
		return
	}

	server, err := NewServer(config)
	if err != nil {
		log.Fatalf("Error occured while instantiating server: %v", err)
		return
	}
	server.Start()
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


// Function to handle a DHCP packet in a new goroutine
func (s *Server) handleDHCPPacket(packet_slice []byte, clientAddr *net.UDPAddr, config c.Configurations) {
	dhcp_packet := gopacket.NewPacket(packet_slice, layers.LayerTypeDHCPv4, gopacket.Default)
	dhcp_layer := dhcp_packet.Layer(layers.LayerTypeDHCPv4)

	// If nil, essentially drop the packet
	if dhcp_packet == nil || dhcp_layer == nil{
		log.Printf("Error, unable to get DHCP packet or layer")
		return
	}

	dhcp, _ := dhcp_layer.(*layers.DHCPv4)

	switch message, _ := getMessageTypeOption(dhcp.Options); message {
	case layers.DHCPMsgTypeDiscover:
		log.Printf("Got Discover")
		s.sendOffer(packet_slice, config)
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

func (s *Server) sendOffer(packet_slice []byte, config c.Configurations) {
	dhcp_packet := gopacket.NewPacket(packet_slice, layers.LayerTypeEthernet, gopacket.Default)
    ethLayer := dhcp_packet.Layer(layers.LayerTypeEthernet)
	ethernetPacket, _ := ethLayer.(*layers.Ethernet)

	buf := gopacket.NewSerializeBuffer()
	// List of layers to later serialize
	var layersToSerialize []gopacket.SerializableLayer

	srcMac, err := net.ParseMAC(config.Metal.HardwareAddr)
	if err != nil {
		log.Fatalf("Error occured while parsing server Hardware addr")
		return
	}
	log.Print("Server srcmac: %v", srcMac.String())

	// Create layer and add it to list to serialize
	ethernetLayer := &layers.Ethernet{
		SrcMAC: srcMac,
		DstMAC: ethernetPacket.SrcMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	layersToSerialize = append(layersToSerialize, ethernetLayer)

	broadcastIP := net.IPv4(255, 255, 255, 255)
	offeredIP := generateAddr()
	log.Printf("broadcastip: %v", broadcastIP.String())
	log.Printf("offered ip: %v", offeredIP.String())

	ipLayer := &layers.IPv4{
		Version: 4,
		TTL: 64,
		SrcIP: net.ParseIP(config.Server.ServerAddr),
		DstIP: broadcastIP,
		Protocol: layers.IPProtocolUDP,
	}
	layersToSerialize = append(layersToSerialize, ipLayer)

	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(67),
		DstPort: layers.UDPPort(68),
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer) // Important for checksum calculation

	layersToSerialize = append(layersToSerialize, udpLayer)


	msgTypeOption := layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeOffer)})
    // Collect them into a DHCPOptions slice
    dhcpOptions := layers.DHCPOptions{
        msgTypeOption,
    }
	dhcpLayer, _ := constructOfferLayer(packet_slice, offeredIP, dhcpOptions, config) // Returns pointer to what was affected
	layersToSerialize = append(layersToSerialize, dhcpLayer)

	// Serialize the packet layers into the buffer
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, layersToSerialize...); err != nil {
		fmt.Printf("error serializing packet: %w", err)
		return
	}

	fmt.Printf("Sending packet bytes to sench")
	s.sendch <- buf.Bytes()
}

