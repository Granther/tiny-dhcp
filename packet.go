package main

import (
	"net"
	"fmt"
	"log"
	"bytes"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	c "gdhcp/config"
	dhcpUtils "gdhcp/dhcp"
)


func (s *Server) createNack(packet_slice []byte, config c.Config) {
	dhcp_packet := gopacket.NewPacket(packet_slice, layers.LayerTypeEthernet, gopacket.Default)
    ethLayer := dhcp_packet.Layer(layers.LayerTypeEthernet)
	ethernetPacket, _ := ethLayer.(*layers.Ethernet)

	buf := gopacket.NewSerializeBuffer()
	var layersToSerialize []gopacket.SerializableLayer

	ethernetLayer := &layers.Ethernet{
		SrcMAC: s.serverMAC,
		DstMAC: ethernetPacket.SrcMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	layersToSerialize = append(layersToSerialize, ethernetLayer)

	broadcastAddr := net.IP{255, 255, 255, 255}

	ipLayer := &layers.IPv4{
		Version: 4,
		TTL: 64,
		SrcIP: s.serverIP, // We always respond on the DHCP ip
		DstIP: broadcastAddr, // We set the Dest to that of the offered IP
		Protocol: layers.IPProtocolUDP,
	}
	layersToSerialize = append(layersToSerialize, ipLayer)

	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(67),
		DstPort: layers.UDPPort(68),
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer) // Important for checksum calculation
	layersToSerialize = append(layersToSerialize, udpLayer)

	dhcpLayer, _ := s.ConstructNackLayer(packet_slice) // Returns pointer to what was affected
	layersToSerialize = append(layersToSerialize, dhcpLayer)

	// Serialize the packet layers into the buffer
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, layersToSerialize...); err != nil {
		fmt.Printf("error serializing packet: %w", err)
		return
	}

	// Send packet byte slice to sendchannel to be sent 
	s.sendch <- buf.Bytes()
}

func (s *Server) ConstructNackLayer(packet_slice []byte) (*layers.DHCPv4, error) {
	DHCPPacket := gopacket.NewPacket(packet_slice, layers.LayerTypeDHCPv4, gopacket.Default)
	discDhcpLayer := DHCPPacket.Layer(layers.LayerTypeDHCPv4)

	lowPacket, ok := discDhcpLayer.(*layers.DHCPv4)
	if !ok {
		log.Fatalf("Error while parsing DHCPv4 layer in packet")
	} 

	dhcpOptions, ok := s.ReadRequestListNack(lowPacket)
	if !ok {
		log.Println("Request list does not exist in Discover")
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
		YourClientIP: lowPacket.YourClientIP, // Your IP is what is offered, what is 'yours'
		ClientHWAddr: lowPacket.ClientHWAddr,
		Options:     *dhcpOptions,
	}

	return dhcpLayer, nil
}

func createClasslessStaticRoute(network string, nextHop net.IP) ([]byte, error) {
	_, ipNet, err := net.ParseCIDR(network)
	if err != nil {
		return nil, fmt.Errorf("invalid network: %v", err)
	}

	prefixLength, _ := ipNet.Mask.Size()
	destinationIP := ipNet.IP.To4()

	// Calculate the number of significant octets
	significantOctets := (prefixLength + 7) / 8

	// Construct the option data
	data := make([]byte, 1+significantOctets+4)
	data[0] = byte(prefixLength)
	copy(data[1:], destinationIP[:significantOctets])
	copy(data[1+significantOctets:], nextHop.To4())

	return data, nil
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

	broadcastAddr := net.IP{255, 255, 255, 255}
	offeredIP := generateAddr()

	ipLayer := &layers.IPv4{
		Version: 4,
		TTL: 64,
		SrcIP: s.serverIP, // We always respond on the DHCP ip
		DstIP: broadcastAddr, // We set the Dest to that of the offered IP
		Protocol: layers.IPProtocolUDP,
	}
	layersToSerialize = append(layersToSerialize, ipLayer)

	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(67),
		DstPort: layers.UDPPort(68),
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer) // Important for checksum calculation
	layersToSerialize = append(layersToSerialize, udpLayer)

	dhcpLayer, _ := s.ConstructOfferLayer(packet_slice, offeredIP) // Returns pointer to what was affected
	layersToSerialize = append(layersToSerialize, dhcpLayer)

	// Serialize the packet layers into the buffer
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, layersToSerialize...); err != nil {
		fmt.Printf("error serializing packet: %w", err)
		return
	}

	// Send packet byte slice to sendchannel to be sent 
	s.sendch <- buf.Bytes()
}

func (s *Server) ConstructOfferLayer(packet_slice []byte, offeredIP net.IP) (*layers.DHCPv4, error) {
	DHCPPacket := gopacket.NewPacket(packet_slice, layers.LayerTypeDHCPv4, gopacket.Default)
	discDhcpLayer := DHCPPacket.Layer(layers.LayerTypeDHCPv4)

	lowPacket, ok := discDhcpLayer.(*layers.DHCPv4)
	if !ok {
		log.Fatalf("Error while parsing DHCPv4 layer in packet")
	} 

	dhcpOptions, ok := s.ReadRequestList(lowPacket)
	if !ok {
		log.Println("Request list does not exist in Discover")
	}

	dhcpOptions = addPaddingToDHCPOptions(dhcpOptions)

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

func (s *Server) ReadRequestListNack(layer *layers.DHCPv4) (*layers.DHCPOptions, bool) {
	// Get RequestParams Option from layer.Options
	// requestList, ok := dhcpUtils.GetDHCPOption(layer.Options, layers.DHCPOptParamsRequest)
	// if !ok {
	// 	return nil, false
	// }

	dhcpOptions := layers.DHCPOptions{}
	
	msgTypeOption := layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeNak)})
	dhcpOptions = append(dhcpOptions, msgTypeOption)
	// // Iterate over Request List, get option requested 
	// for _, req := range requestList.Data {
	// 	if s.optionsMap[layers.DHCPOpt(req)] == nil {
	// 		continue
	// 	}
	// 	r := s.optionsMap[layers.DHCPOpt(req)].ToBytes()
	// 	if r == nil {
	// 		continue
	// 	}

	// 	op := layers.NewDHCPOption(layers.DHCPOpt(req), r) 
	// 	dhcpOptions = append(dhcpOptions, op)
	// }

	dhcpServerIP := layers.NewDHCPOption(layers.DHCPOptServerID, s.serverIP.To4())
	endOptions := layers.NewDHCPOption(layers.DHCPOptEnd, []byte{})

	dhcpOptions = append(dhcpOptions, dhcpServerIP)
	dhcpOptions = append(dhcpOptions, endOptions)

	// We return a pointer so we can append other things later, such as opt 255
	return &dhcpOptions, true
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

	// network := "192.168.1.0/24"
	// nextHop := net.ParseIP("192.168.1.1")

	// routeData, err := createClasslessStaticRoute(network, nextHop)
	// if err != nil {
	// 	fmt.Println("Error:", err)
	// }

	// dhcpCIDRRoute := layers.NewDHCPOption(layers.DHCPOptClasslessStaticRoute, routeData)
	dhcpServerIP := layers.NewDHCPOption(layers.DHCPOptServerID, s.serverIP.To4())
	endOptions := layers.NewDHCPOption(layers.DHCPOptEnd, []byte{})


	// dhcpOptions = append(dhcpOptions, dhcpCIDRRoute)
	dhcpOptions = append(dhcpOptions, dhcpServerIP)
	dhcpOptions = append(dhcpOptions, endOptions)

	// We return a pointer so we can append other things later, such as opt 255
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

	dhcpOptions, ok := s.ReadRequestListAck(lowPacket)
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

func (s *Server) ReadRequestListAck(layer *layers.DHCPv4) (*layers.DHCPOptions, bool) {
	// Get RequestParams Option from layer.Options
	requestList, ok := dhcpUtils.GetDHCPOption(layer.Options, layers.DHCPOptParamsRequest)
	if !ok {
		return nil, false
	}

	dhcpOptions := layers.DHCPOptions{}
	
	msgTypeOption := layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeAck)})
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

	network := "192.168.1.0/24"
	nextHop := net.ParseIP("192.168.1.1")

	routeData, err := createClasslessStaticRoute(network, nextHop)
	if err != nil {
		fmt.Println("Error:", err)
	}
	
	dhcpLeaseTime := layers.NewDHCPOption(layers.DHCPOptLeaseTime, s.optionsMap[layers.DHCPOptLeaseTime].ToBytes())
	dhcpCIDRRoute := layers.NewDHCPOption(layers.DHCPOptClasslessStaticRoute, routeData)
	dhcpServerIP := layers.NewDHCPOption(layers.DHCPOptServerID, s.serverIP.To4())
	endOptions := layers.NewDHCPOption(layers.DHCPOptEnd, []byte{})

	dhcpOptions = append(dhcpOptions, dhcpCIDRRoute)
	dhcpOptions = append(dhcpOptions, dhcpLeaseTime)
	dhcpOptions = append(dhcpOptions, dhcpServerIP)
	dhcpOptions = append(dhcpOptions, endOptions)

	// We return a pointer so we can append other things later, such as opt 255
	return &dhcpOptions, true
}

func (s *Server) createAck(packet_slice []byte, config c.Config) {
    dhcp_packet := gopacket.NewPacket(packet_slice, layers.LayerTypeDHCPv4, gopacket.Default)
	discDhcpLayer := dhcp_packet.Layer(layers.LayerTypeDHCPv4)
    
    // Debug: Print all layers
    // for _, layer := range dhcp_packet.Layers() {
    //     log.Printf("Layer: %v", layer.LayerType())
    // }

    // ethLayer := dhcp_packet.Layer(layers.LayerTypeEthernet)
    // if ethLayer == nil {
    //     log.Println("Error: No Ethernet layer found")
    //     return
    // }

	lowPacket, ok := discDhcpLayer.(*layers.DHCPv4)
	if !ok {
		log.Fatalf("Error while parsing DHCPv4 layer in packet in createack")
	} 



	// dhcpOptions, ok := s.ReadRequestList(lowPacket)
	// if !ok {
	// 	log.Println("Request list does not exist in Discover")
	// }

    // ethernetPacket, ok := ethLayer.(*layers.Ethernet)
    // if !ok {
    //     log.Println("Error: Failed to cast to Ethernet layer")
    //     return
    // }

    // srcMAC := ethernetPacket.SrcMAC
	srcMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
    log.Printf("Ethernet SrcMAC: %s", srcMAC.String())

    // Try to get the DHCP layer
    dhcpLayer := dhcp_packet.Layer(layers.LayerTypeDHCPv4)
    if dhcpLayer != nil {
        dhcpPacket, ok := dhcpLayer.(*layers.DHCPv4)
        if ok {
            log.Printf("DHCP ClientHWAddr: %s", dhcpPacket.ClientHWAddr.String())
            // Use this MAC address instead if it's available
            srcMAC = dhcpPacket.ClientHWAddr
        }
    }

    buf := gopacket.NewSerializeBuffer()
    var layersToSerialize []gopacket.SerializableLayer
    ethernetLayer := &layers.Ethernet{
        SrcMAC:       s.serverMAC,
        DstMAC:       srcMAC,
        EthernetType: layers.EthernetTypeIPv4,
    }
    layersToSerialize = append(layersToSerialize, ethernetLayer)

	broadcastAddr := net.IP{255, 255, 255, 255}
	// offeredIP := generateAddr()
	// _, ok := discDhcpLayer.(*layers.DHCPv4)
	// if !ok {
	// 	log.Println("Error converting from ")
	// }

	requestedIp, rok := dhcpUtils.GetDHCPOption(lowPacket.Options, layers.DHCPOptRequestIP)
	if !rok {
		log.Printf("Unable to get Requested IP from reqeuest packet")
	}

	// log.Println(requestedIp.Data)
	// req := net.IP(requestedIp.Data)

	ipLayer := &layers.IPv4{
		Version: 4,
		TTL: 64,
		SrcIP: s.serverIP, // We always respond on the DHCP ip
		DstIP: broadcastAddr, // We set the Dest to that of the offered IP
		Protocol: layers.IPProtocolUDP,
	}
	layersToSerialize = append(layersToSerialize, ipLayer)

	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(67),
		DstPort: layers.UDPPort(68),
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer) // Important for checksum calculation
	layersToSerialize = append(layersToSerialize, udpLayer)

	dhcpLayerConst, _ := s.ConstructAckLayer(packet_slice, requestedIp.Data) // Returns pointer to what was affected
	layersToSerialize = append(layersToSerialize, dhcpLayerConst)

	// Serialize the packet layers into the buffer
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, layersToSerialize...); err != nil {
		fmt.Printf("error serializing packet: %w", err)
		return
	}

	// Send packet byte slice to sendchannel to be sent 
	s.sendch <- buf.Bytes()
}

func addPaddingToDHCPOptions(options *layers.DHCPOptions) *layers.DHCPOptions {
	// Determine current length of options
	totalLength := 0
	for _, opt := range *options {
		totalLength += int(opt.Length) + 2 // Option type (1 byte) + length (1 byte) + data
	}

	var oop layers.DHCPOptions 
	// Check if total length is a multiple of 4 (32 bits)
	if totalLength%4 != 0 {
		paddingLength := 4 - (totalLength % 4)
		padding := layers.DHCPOption{
			Type:   0,  // Padding uses type 0x00 (RFC 2131 padding)
			Length: uint8(paddingLength),
			Data:   bytes.Repeat([]byte{0x00}, paddingLength),
		}
		oop = append(*options, padding)
	}

	return &oop
}