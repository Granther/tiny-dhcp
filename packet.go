package main

import (
	"net"
	"fmt"
	"log"
	"slices"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	c "gdhcp/config"
	dhcpUtils "gdhcp/dhcp"
	database "gdhcp/database"
)

// Fixes mac addr to be correct size if sent as locally administered, returns true if LA'd
func processMAC(mac net.HardwareAddr) (net.HardwareAddr, bool, error) {
	if len(mac) > 6 {
		log.Println("Debug: Mac is larger than 6 bytes, fixing...")
		mac = mac[1:]
		return mac, true, nil
	} else if len(mac) == 6 {
		log.Println("Debug: Mac is good")
		return mac, false, nil
	} else {
		return net.HardwareAddr{}, false, fmt.Errorf("Error processing mac addr")
	}
}

func extractMAC(dhcpLayer *layers.DHCPv4) (net.HardwareAddr, error) {
	clientMAC, ok := dhcpUtils.GetDHCPOption(dhcpLayer.Options, layers.DHCPOptClientID)
	if !ok {
		return nil, fmt.Errorf("Unable to get client mac from dhcp layer")
	}

	mac, _, err := processMAC(net.HardwareAddr(clientMAC.Data)); if err != nil {
		return nil, fmt.Errorf("Error processing mac to usable form: %v", err)
	}

	return mac, nil
}

func (s *Server) createOffer(packetSlice []byte, config c.Config) error {
	dhcpLayer, _ := gopacket.NewPacket(packetSlice, layers.LayerTypeDHCPv4, gopacket.Default).Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4)

	clientMAC, err := extractMAC(dhcpLayer); if err != nil {
		return err
	}

	var offeredIP net.IP
	requestedIP, ok := dhcpUtils.GetDHCPOption(dhcpLayer.Options, layers.DHCPOptRequestIP)
	if !ok {
		log.Println("Attempted to get requested IP from discover, didn't find it, generating addr")
		offeredIP, err = database.GenerateIP(s.db); if err != nil {
			return fmt.Errorf("%w", err)
		}
	} else {
		log.Println("Debug: Got requested IP from discover, checking availability...")
		if database.IsIPAvailable(s.db, requestedIP.Data) {
			log.Printf("Debug: Looks like its available, using it: %v\n", requestedIP.Data)
			offeredIP = requestedIP.Data
		} else {
			log.Println("Debug: Generating IP because requested one is not available")
			oldIP := database.IsMACLeased(s.db, clientMAC)
			if oldIP != nil {
				offeredIP = oldIP
			} else {
				offeredIP, err = database.GenerateIP(s.db); if err != nil {
					return fmt.Errorf("%w", err)
				}
			}
		}
	}

	log.Printf("Offered IP: %v\n", offeredIP.String())

	offerLayer, err := s.ConstructOfferLayer(dhcpLayer, offeredIP); if err != nil {
		return err
	}
	packetPtr, err := s.BuildStdPacket(offeredIP, clientMAC, offerLayer); if err != nil {
		return err
	}
	packetBuf := *packetPtr

	log.Println("Sending offer packet")
	s.sendch <- packetBuf.Bytes()

	return nil 
}

func (s *Server) BuildStdPacket(dstIP net.IP, dstMAC net.HardwareAddr, dhcpLayer *layers.DHCPv4) (*gopacket.SerializeBuffer, error) {
	buf := gopacket.NewSerializeBuffer()
	var layersToSerialize []gopacket.SerializableLayer

	ethernetLayer := &layers.Ethernet{
		SrcMAC: s.serverMAC,
		DstMAC: dstMAC, 
		EthernetType: layers.EthernetTypeIPv4,
	}
	layersToSerialize = append(layersToSerialize, ethernetLayer)

	ipLayer := &layers.IPv4{
		Version: 4,
		TTL: 64,
		SrcIP: s.serverIP, // We always respond on the DHCP ip
		DstIP: dstIP, // We set the Dest to that of the offered IP
		Protocol: layers.IPProtocolUDP,
	}
	layersToSerialize = append(layersToSerialize, ipLayer)

	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(67),
		DstPort: layers.UDPPort(68),
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer) // Important for checksum calculation
	layersToSerialize = append(layersToSerialize, udpLayer)
	layersToSerialize = append(layersToSerialize, dhcpLayer)

	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, layersToSerialize...); err != nil {
		return nil, fmt.Errorf("error serializing packet: %w", err)
	}

	return &buf, nil
}

func (s *Server) createAck(packetSlice []byte, config c.Config) error {
	dhcpLayer, _ := gopacket.NewPacket(packetSlice, layers.LayerTypeDHCPv4, gopacket.Default).Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4)

	clientMAC, err := extractMAC(dhcpLayer); if err != nil {
		return err
	}

	var requestedIP net.IP
	requestedIPOpt, ok := dhcpUtils.GetDHCPOption(dhcpLayer.Options, layers.DHCPOptRequestIP)
	if !ok {
		log.Println("Debug: Attempted to get requested IP from request, didn't find it, exiting")
		return fmt.Errorf("Requested IP option not in request")
	} else {
		requestedIP = requestedIPOpt.Data
		oldIP := database.IsMACLeased(s.db, clientMAC)
		if slices.Compare(oldIP, requestedIP) == 0 {
			log.Println("Mac is leased and it is leased to the requested IP, renewing...")
			// Renew the ip lease
			err := database.LeaseIP(s.db, requestedIP, clientMAC, s.config.DHCP.LeaseLen); if err != nil {
				return fmt.Errorf("Unable to renew lease for requested IP: %w\n", err)
			}
		}
		log.Println("Debug: Got requested IP from request, checking availability...")
		if database.IsIPAvailable(s.db, requestedIP) {
			log.Printf("Debug: Looks like its available, using it: %v\n", requestedIP)
			err := database.LeaseIP(s.db, requestedIP, clientMAC, s.config.DHCP.LeaseLen); if err != nil {
				return fmt.Errorf("Unable to create lease for requested IP: %w\n", err)
			}
		} else {
			log.Println("Debug: Requested IP is not available, sending Nack")
			err := s.createNack(); if err != nil {
				return fmt.Errorf("Error sending nack in response to request")
			}
		}
	}

	log.Printf("Requested IP: %v\n", requestedIP.String())

	ackLayer, err := s.ConstructAckLayer(dhcpLayer, requestedIP); if err != nil {
		return err
	}
	packetPtr, err := s.BuildStdPacket(requestedIP, clientMAC, ackLayer); if err != nil {
		return err
	}
	packetBuf := *packetPtr

	log.Println("Sending ack packet")
	s.sendch <- packetBuf.Bytes()

	return nil 
}

func (s *Server) ConstructOfferLayer(dhcpLayer *layers.DHCPv4, offeredIP net.IP) (*layers.DHCPv4, error) {
	dhcpOptions, ok := s.ReadRequestList(dhcpLayer)
	if !ok {
		slog.Warm("Request list does not exist in Discover")
	}

	var hardwareLen uint8 = 6 // MAC is commonly 6
	var hardwareOpts uint8 = 0 // None I guess, maybe specify unicast or something
	xid := lowPacket.Xid // Carry over XID, "We are in the same conversation"
	secs := lowPacket.Secs // All secs were 1 in notes

	dhcpLayer := &layers.DHCPv4{
		Operation:    layers.DHCPOpReply, // Type of Bootp reply, always reply when coming from server
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  hardwareLen,
		HardwareOpts: hardwareOpts, 
		Xid:          xid, // Need this from discover
		Secs:         secs, // Make this up for now
		YourClientIP: offeredIP, // Your IP is what is offered, what is 'yours'
		ClientHWAddr: lowPacket.ClientHWAddr,
		Options:     *dhcpOptions,
	}

	return dhcpLayer, nil
}

func (s *Server) ReadRequestList(layer *layers.DHCPv4) (*layers.DHCPOptions, bool) {
	// Get RequestParams Option from layer.Options
	requestList, ok := dhcpUtils.GetDHCPOption(layer.Options, layers.DHCPOptParamsRequest)
	if !ok {
		return nil, false
	}

	dhcpOptions := layers.DHCPOptions{}
	
	msgTypeOption := layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeOffer)})
	dhcpOptions = append(dhcpOptions, msgTypeOption)
	// Iterate over Request List, get option requested 
	for _, req := range requestList.Data {
		if s.optionsMap[layers.DHCPOpt(req)] == nil {
			continue
		}
		r := s.optionsMap[layers.DHCPOpt(req)].ToBytes()
		if r == nil {
			continue
		}

		op := layers.NewDHCPOption(layers.DHCPOpt(req), r) 
		dhcpOptions = append(dhcpOptions, op)
	}

	dhcpLeaseTime := layers.NewDHCPOption(layers.DHCPOptLeaseTime, s.optionsMap[layers.DHCPOptLeaseTime].ToBytes())
	dhcpServerIP := layers.NewDHCPOption(layers.DHCPOptServerID, s.serverIP.To4())
	endOptions := layers.NewDHCPOption(layers.DHCPOptEnd, []byte{})

	dhcpOptions	= append(dhcpOptions, dhcpLeaseTime)
	dhcpOptions = append(dhcpOptions, dhcpServerIP)
	dhcpOptions = append(dhcpOptions, endOptions)

	return &dhcpOptions, true
}

func (s *Server) ConstructAckLayer(packet_slice []byte, offeredIP net.IP) (*layers.DHCPv4, error) {
	DHCPPacket := gopacket.NewPacket(packet_slice, layers.LayerTypeDHCPv4, gopacket.Default)
	discDhcpLayer := DHCPPacket.Layer(layers.LayerTypeDHCPv4)

	if discDhcpLayer == nil {
		log.Fatalf("discDhcplayer is nil lol!")
	}

	lowPacket, ok := discDhcpLayer.(*layers.DHCPv4)
	if !ok {
		log.Println("Error while parsing DHCPv4 layer in packet")
	} 

	dhcpOptions, ok := s.ReadRequestList(lowPacket)
	if !ok {
		log.Println("Request list does not exist in Discover")
	}

	var hardwareLen uint8 = 6 // MAC is commonly 6
	var flags uint16 = 0x8000
	var hardwareOpts uint8 = 0 // None I guess, maybe specify unicast or something
	xid := lowPacket.Xid // Carry over XID, "We are in the same conversation"
	secs := lowPacket.Secs // All secs were 1 in notes

	dhcpLayer := &layers.DHCPv4{
		Operation:    layers.DHCPOpReply, // Type of Bootp reply, always reply when coming from server
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  hardwareLen,
		HardwareOpts: hardwareOpts, 
		Flags:		  flags,
		Xid:          xid, // Need this from discover
		Secs:         secs, // Make this up for now
		YourClientIP: offeredIP, // Your IP is what is offered, what is 'yours'
		ClientHWAddr: lowPacket.ClientHWAddr,
		Options:     *dhcpOptions,
	}

	return dhcpLayer, nil
}

// func addPaddingToDHCPOptions(options *layers.DHCPOptions) *layers.DHCPOptions {
// 	// Determine current length of options
// 	totalLength := 0
// 	for _, opt := range *options {
// 		totalLength += int(opt.Length) + 2 // Option type (1 byte) + length (1 byte) + data
// 	}

// 	var oop layers.DHCPOptions 
// 	// Check if total length is a multiple of 4 (32 bits)
// 	if totalLength%4 != 0 {
// 		paddingLength := 4 - (totalLength % 4)
// 		padding := layers.DHCPOption{
// 			Type:   0,  // Padding uses type 0x00 (RFC 2131 padding)
// 			Length: uint8(paddingLength),
// 			Data:   bytes.Repeat([]byte{0x00}, paddingLength),
// 		}
// 		oop = append(*options, padding)
// 	}

// 	return &oop
// }

// func (s *Server) ReadRequestListNack(layer *layers.DHCPv4) (*layers.DHCPOptions, bool) {
// 	// Get RequestParams Option from layer.Options
// 	// requestList, ok := dhcpUtils.GetDHCPOption(layer.Options, layers.DHCPOptParamsRequest)
// 	// if !ok {
// 	// 	return nil, false
// 	// }

// 	dhcpOptions := layers.DHCPOptions{}
	
// 	msgTypeOption := layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeNak)})
// 	dhcpOptions = append(dhcpOptions, msgTypeOption)
// 	// // Iterate over Request List, get option requested 
// 	// for _, req := range requestList.Data {
// 	// 	if s.optionsMap[layers.DHCPOpt(req)] == nil {
// 	// 		continue
// 	// 	}
// 	// 	r := s.optionsMap[layers.DHCPOpt(req)].ToBytes()
// 	// 	if r == nil {
// 	// 		continue
// 	// 	}

// 	// 	op := layers.NewDHCPOption(layers.DHCPOpt(req), r) 
// 	// 	dhcpOptions = append(dhcpOptions, op)
// 	// }

// 	dhcpServerIP := layers.NewDHCPOption(layers.DHCPOptServerID, s.serverIP.To4())
// 	endOptions := layers.NewDHCPOption(layers.DHCPOptEnd, []byte{})

// 	dhcpOptions = append(dhcpOptions, dhcpServerIP)
// 	dhcpOptions = append(dhcpOptions, endOptions)

// 	// We return a pointer so we can append other things later, such as opt 255
// 	return &dhcpOptions, true
// }

// func (s *Server) ConstructNackLayer(packet_slice []byte) (*layers.DHCPv4, error) {
// 	DHCPPacket := gopacket.NewPacket(packet_slice, layers.LayerTypeDHCPv4, gopacket.Default)
// 	discDhcpLayer := DHCPPacket.Layer(layers.LayerTypeDHCPv4)

// 	lowPacket, ok := discDhcpLayer.(*layers.DHCPv4)
// 	if !ok {
// 		log.Fatalf("Error while parsing DHCPv4 layer in packet")
// 	} 

// 	dhcpOptions, ok := s.ReadRequestListNack(lowPacket)
// 	if !ok {
// 		log.Println("Request list does not exist in Discover")
// 	}

// 	var hardwareLen uint8 = 6 // MAC is commonly 6
// 	var hardwareOpts uint8 = 0 // None I guess, maybe specify unicast or something
// 	xid := lowPacket.Xid // Carry over XID, "We are in the same conversation"
// 	secs := lowPacket.Secs // All secs were 1 in notes

// 	dhcpLayer := &layers.DHCPv4{
// 		Operation:    layers.DHCPOpReply, // Type of Bootp reply, always reply when coming from server
// 		HardwareType: layers.LinkTypeEthernet,
// 		HardwareLen:  hardwareLen,
// 		HardwareOpts: hardwareOpts, 
// 		Xid:          xid, // Need this from discover
// 		Secs:         secs, // Make this up for now
// 		YourClientIP: lowPacket.YourClientIP, // Your IP is what is offered, what is 'yours'
// 		ClientHWAddr: lowPacket.ClientHWAddr,
// 		Options:     *dhcpOptions,
// 	}

// 	return dhcpLayer, nil
// }

    // dhcp_packet := gopacket.NewPacket(packet_slice, layers.LayerTypeDHCPv4, gopacket.Default)
	// discDhcpLayer := dhcp_packet.Layer(layers.LayerTypeDHCPv4)

	// lowPacket, ok := discDhcpLayer.(*layers.DHCPv4)
	// if !ok {
	// 	log.Fatalf("Error while parsing DHCPv4 layer in packet in createack")
	// 	return	
	// }

	// broadcastAddr := net.IP{255, 255, 255, 255}

	// requestedIp, rok := dhcpUtils.GetDHCPOption(lowPacket.Options, layers.DHCPOptRequestIP)
	// if !rok {
	// 	log.Printf("Unable to get Requested IP from reqeuest packet")
	// }

	// log.Println(requestedIp.Data)
	// req := net.IP(requestedIp.Data)

// func (s *Server) createNack(packet_slice []byte, config c.Config) {
// 	dhcp_packet := gopacket.NewPacket(packet_slice, layers.LayerTypeEthernet, gopacket.Default)
// 	ethLayer := dhcp_packet.Layer(layers.LayerTypeEthernet)
// 	ethernetPacket, _ := ethLayer.(*layers.Ethernet)

// 	buf := gopacket.NewSerializeBuffer()
// 	var layersToSerialize []gopacket.SerializableLayer

// 	ethernetLayer := &layers.Ethernet{
// 		SrcMAC: s.serverMAC,
// 		DstMAC: ethernetPacket.SrcMAC,
// 		EthernetType: layers.EthernetTypeIPv4,
// 	}
// 	layersToSerialize = append(layersToSerialize, ethernetLayer)

// 	broadcastAddr := net.IP{255, 255, 255, 255}

// 	ipLayer := &layers.IPv4{
// 		Version: 4,
// 		TTL: 64,
// 		SrcIP: s.serverIP, // We always respond on the DHCP ip
// 		DstIP: broadcastAddr, // We set the Dest to that of the offered IP
// 		Protocol: layers.IPProtocolUDP,
// 	}
// 	layersToSerialize = append(layersToSerialize, ipLayer)

// 	udpLayer := &layers.UDP{
// 		SrcPort: layers.UDPPort(67),
// 		DstPort: layers.UDPPort(68),
// 	}
// 	udpLayer.SetNetworkLayerForChecksum(ipLayer) // Important for checksum calculation
// 	layersToSerialize = append(layersToSerialize, udpLayer)

// 	dhcpLayer, _ := s.ConstructNackLayer(packet_slice) // Returns pointer to what was affected
// 	layersToSerialize = append(layersToSerialize, dhcpLayer)

// 	// Serialize the packet layers into the buffer
// 	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, layersToSerialize...); err != nil {
// 		fmt.Printf("error serializing packet: %w", err)
// 		return
// 	}

// 	// Send packet byte slice to sendchannel to be sent 
// 	s.sendch <- buf.Bytes()
// }

// func createClasslessStaticRoute(network string, nextHop net.IP) ([]byte, error) {
// 	_, ipNet, err := net.ParseCIDR(network)
// 	if err != nil {
// 		return nil, fmt.Errorf("invalid network: %v", err)
// 	}

// 	prefixLength, _ := ipNet.Mask.Size()
// 	destinationIP := ipNet.IP.To4()

// 	// Calculate the number of significant octets
// 	significantOctets := (prefixLength + 7) / 8

// 	// Construct the option data
// 	data := make([]byte, 1+significantOctets+4)
// 	data[0] = byte(prefixLength)
// 	copy(data[1:], destinationIP[:significantOctets])
// 	copy(data[1+significantOctets:], nextHop.To4())

// 	return data, nil
// }

// func (s *Server) ReadRequestListAck(layer *layers.DHCPv4) (*layers.DHCPOptions, bool) {
// 	// Get RequestParams Option from layer.Options
// 	requestList, ok := dhcpUtils.GetDHCPOption(layer.Options, layers.DHCPOptParamsRequest)
// 	if !ok {
// 		return nil, false
// 	}

// 	dhcpOptions := layers.DHCPOptions{}
	
// 	msgTypeOption := layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeAck)})
// 	dhcpOptions = append(dhcpOptions, msgTypeOption)
// 	// Iterate over Request List, get option requested 
// 	for _, req := range requestList.Data {
// 		if s.optionsMap[layers.DHCPOpt(req)] == nil {
// 			continue
// 		}
// 		r := s.optionsMap[layers.DHCPOpt(req)].ToBytes()
// 		if r == nil {
// 			continue
// 		}

// 		op := layers.NewDHCPOption(layers.DHCPOpt(req), r) 
// 		dhcpOptions = append(dhcpOptions, op)
// 	}

// 	network := "192.168.1.0/24"
// 	nextHop := net.ParseIP("192.168.1.1")

// 	routeData, err := createClasslessStaticRoute(network, nextHop)
// 	if err != nil {
// 		fmt.Println("Error:", err)
// 	}
	
// 	dhcpLeaseTime := layers.NewDHCPOption(layers.DHCPOptLeaseTime, s.optionsMap[layers.DHCPOptLeaseTime].ToBytes())
// 	dhcpCIDRRoute := layers.NewDHCPOption(layers.DHCPOptClasslessStaticRoute, routeData)
// 	dhcpServerIP := layers.NewDHCPOption(layers.DHCPOptServerID, s.serverIP.To4())
// 	endOptions := layers.NewDHCPOption(layers.DHCPOptEnd, []byte{})

// 	dhcpOptions = append(dhcpOptions, dhcpCIDRRoute)
// 	dhcpOptions = append(dhcpOptions, dhcpLeaseTime)
// 	dhcpOptions = append(dhcpOptions, dhcpServerIP)
// 	dhcpOptions = append(dhcpOptions, endOptions)

// 	// We return a pointer so we can append other things later, such as opt 255
// 	return &dhcpOptions, true
// }

	// buf := gopacket.NewSerializeBuffer()
	// var layersToSerialize []gopacket.SerializableLayer

	// ethernetLayer := &layers.Ethernet{
	// 	SrcMAC: s.serverMAC,
	// 	DstMAC: mac, 
	// 	EthernetType: layers.EthernetTypeIPv4,
	// }
	// layersToSerialize = append(layersToSerialize, ethernetLayer)

	// ipLayer := &layers.IPv4{
	// 	Version: 4,
	// 	TTL: 64,
	// 	SrcIP: s.serverIP, // We always respond on the DHCP ip
	// 	DstIP: offeredIP, // We set the Dest to that of the offered IP
	// 	Protocol: layers.IPProtocolUDP,
	// }
	// layersToSerialize = append(layersToSerialize, ipLayer)

	// udpLayer := &layers.UDP{
	// 	SrcPort: layers.UDPPort(67),
	// 	DstPort: layers.UDPPort(68),
	// }
	// udpLayer.SetNetworkLayerForChecksum(ipLayer) // Important for checksum calculation
	// layersToSerialize = append(layersToSerialize, udpLayer)

	// dhcpLayer, _ := s.ConstructOfferLayer(packet_slice, offeredIP) // Returns pointer to what was affected
	// layersToSerialize = append(layersToSerialize, dhcpLayer)

	// // Serialize the packet layers into the buffer
	// if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, layersToSerialize...); err != nil {
	// 	return fmt.Errorf("error serializing packet: %w", err)
	// }