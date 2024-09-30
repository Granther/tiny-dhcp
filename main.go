package main

import (
	"net"
	"fmt"
	"log"
	// "encoding/binary"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	// "github.com/spf13/viper"

	c "gdhcp/config"
	dhcpUtils "gdhcp/dhcp"
	deviceUtils "gdhcp/device"
	options "gdhcp/options"
)

type Server struct {
	conn		*net.UDPConn
	handle		*pcap.Handle
	serverIP	net.IP
	serverMAC	net.HardwareAddr
	config		c.Config
	optionsMap	map[layers.DHCPOpt]options.DHCPOptionValue
	workerPool	chan struct{}
	packetch 	chan packetJob
	sendch		chan []byte
	quitch		chan struct{}
}

type packetJob struct {
    data        []byte
    clientAddr  *net.UDPAddr
}

func NewServer(config c.Config) (*Server, error) {
	iface, err := net.InterfaceByName(config.Server.ListenInterface)
	if err != nil {
		log.Fatalf("Failed to get interface: %v", err)
		os.Exit(1)
	}

	listenAddr, err := deviceUtils.GetUDPAddr(iface)
	if err != nil {
		log.Fatalf("Error occured while creating listen address struct, please review the interface configuration: %w", err)
		os.Exit(1)
	}
	
	nlistenAddr := net.UDPAddr{IP: net.IP{255, 255, 255, 255},  Port: 67}
	conn, err := net.ListenUDP("udp", &nlistenAddr)
	if err != nil {
        return nil, fmt.Errorf("Error creating server UDP listener: %v", err)
    }

	// WINDOWS DEV
	// Windows interface: \\Device\\NPF_{3C62326A-1389-4DB7-BCF8-55747D0B8757}
	// handle, err := pcap.OpenLive("\\Device\\NPF_{3C62326A-1389-4DB7-BCF8-55747D0B8757}", 1500, false, pcap.BlockForever)

	handle, err := pcap.OpenLive(iface.Name, 1500, false, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("Could not open pcap device: %w", err)
	}

	optionsMap := options.CreateOptionMap(config)
	numWorkers := config.Server.NumWorkers

	// fmt.Println("%v", optionsMap[layers.DHCPOptBroadcastAddr])
	// fmt.Println("%v", optionsMap[layers.DHCPOptRouter])

	return &Server{
		conn:		conn,
		handle:		handle,
		serverIP:	listenAddr.IP,
		serverMAC:	iface.HardwareAddr,
		config:		config,
		optionsMap: optionsMap,
		workerPool:	make(chan struct{}, numWorkers),
		packetch:	make(chan packetJob, 1000), // Can hold 1000 packets
		sendch:		make(chan []byte, 1000), // Can hold 1000 queued packets to be sent
		quitch:		make(chan struct{}),
	}, nil
}

func (s *Server) Start() error {
	log.Println("Starting server...")

	numWorkers := s.config.Server.NumWorkers
	for i := 0; i < numWorkers; i++ {
		go s.worker()
	}

	go s.receivePackets()
	go s.sendPackets()

	log.Println("Server is now listening for packets/quitch")
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

func main() {
	config, err := c.ReadConfig("."); if err != nil {
		log.Fatalf("Error parsing config file: %v", err)
		os.Exit(1)
		return
	}

	server, err := NewServer(config)
	if err != nil {
		log.Fatalf("Error occured while instantiating server: %v", err)
		return
	}
	server.Start()
}

// Function to handle a DHCP packet in a new goroutine
func (s *Server) handleDHCPPacket(packet_slice []byte, clientAddr *net.UDPAddr, config c.Config) {
	dhcp_packet := gopacket.NewPacket(packet_slice, layers.LayerTypeDHCPv4, gopacket.Default)
	dhcp_layer := dhcp_packet.Layer(layers.LayerTypeDHCPv4)

	// If nil, essentially drop the packet
	if dhcp_packet == nil || dhcp_layer == nil{
		log.Printf("Error, unable to get DHCP packet or layer")
		return
	}
	dhcp, _ := dhcp_layer.(*layers.DHCPv4)

	switch message, _ := dhcpUtils.GetMessageTypeOption(dhcp.Options); message {
	case layers.DHCPMsgTypeDiscover:
		log.Printf("Got Discover")
		s.createOffer(packet_slice, config)
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

func generateAddr() (net.IP) {
	return net.IP{192, 168, 1, 180}
}

func (s *Server) createOffer(packet_slice []byte, config c.Config) {
	dhcp_packet := gopacket.NewPacket(packet_slice, layers.LayerTypeEthernet, gopacket.Default)
    ethLayer := dhcp_packet.Layer(layers.LayerTypeEthernet)

	// dhcpLayer, _ := dhcp_packet.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4)
	ethernetPacket, _ := ethLayer.(*layers.Ethernet)

	buf := gopacket.NewSerializeBuffer()
	var layersToSerialize []gopacket.SerializableLayer

	ethernetLayer := &layers.Ethernet{
		SrcMAC: s.serverMAC,
		DstMAC: ethernetPacket.SrcMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	layersToSerialize = append(layersToSerialize, ethernetLayer)

	broadcastIP := net.IPv4(255, 255, 255, 255)
	offeredIP := generateAddr()

	ipLayer := &layers.IPv4{
		Version: 4,
		TTL: 64,
		SrcIP: s.serverIP,
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

	// Converts const to byte, then wraps byte in byte slice cause NewDHCPOption takes a byte slice
	// msgTypeOption := layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeOffer)})
	// // subnetMaskOption := layers.NewDHCPOption(layers.DHCPOptSubnetMask, subnet)
	// gatewayOption := layers.NewDHCPOption(layers.DHCPOptRouter, s.optionsMap[layers.DHCPOptRouter].ToBytes())
	// // dnsOption := layers.NewDHCPOption(layers.DHCPOptDNS, []byte(net.ParseIP(config.DHCP.DNSServer).To4()))
	// leaseLenOption := layers.NewDHCPOption(layers.DHCPOptLeaseTime, s.optionsMap[layers.DHCPOptLeaseTime].ToBytes())

    // Collect them into a DHCPOptions slice

	// dhcpOptions := options.ReadRequestList(dhcpLayer)

    // dhcpOptions := layers.DHCPOptions{
    //     msgTypeOption,
	// 	// subnetMaskOption,
	// 	gatewayOption,
	// 	// dnsOption,
	// 	leaseLenOption,
    // }
	dhcpLayer, _ := dhcpUtils.ConstructOfferLayer(packet_slice, offeredIP, config) // Returns pointer to what was affected
	layersToSerialize = append(layersToSerialize, dhcpLayer)

	// Serialize the packet layers into the buffer
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, layersToSerialize...); err != nil {
		fmt.Printf("error serializing packet: %w", err)
		return
	}

	// Send packet byte slice to sendchannel to be sent 
	s.sendch <- buf.Bytes()
}

// func readConfig() (c.Configur, error) {
	// 	viper.SetConfigName("config")
	// 	viper.AddConfigPath(".")
	// 	viper.SetConfigType("yml")
	// 	var config c.Configurations
	
	// 	if err := viper.ReadInConfig(); err != nil {
	// 		return config, fmt.Errorf("Error reading config file, %s", err)
	// 	}
	
	// 	err := viper.Unmarshal(&config)
	// 	if err != nil {
	// 		return config, fmt.Errorf("Error decoding from struct, %s", err)
	// 	}
	
	// 	return config, nil
	// }