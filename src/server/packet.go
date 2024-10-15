package server

import (
	"net"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	dhcpUtils "gdhcp/dhcp"
	database "gdhcp/database"
)

// Fixes mac addr to be correct size if sent as locally administered, returns true if LA'd
func processMAC(mac net.HardwareAddr) (net.HardwareAddr, bool, error) {
	if len(mac) > 6 {
		slog.Debug("Mac is larger than 6 bytes, fixing...")
		mac = mac[1:]
		return mac, true, nil
	} else if len(mac) == 6 {
		slog.Debug("Mac is good")
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

func (s *Server) createNack(dhcpLayer *layers.DHCPv4) error {
	clientMAC := dhcpLayer.ClientHWAddr


	nackLayer, err := s.constructNackLayer(dhcpLayer); if err != nil {
		return err
	}

	broadcastAddr := net.IP{255, 255, 255, 255}
	packetPtr, err := s.buildStdPacket(broadcastAddr, clientMAC, nackLayer); if err != nil {
		return err
	}
	packetBuf := *packetPtr

	slog.Info("Sending nak to client mac: %v", clientMAC.String())
	s.sendch <- packetBuf.Bytes()

	return nil 
}

func (s *Server) constructNackLayer(requestDhcpLayer *layers.DHCPv4) (*layers.DHCPv4, error) {
	dhcpOptions := layers.DHCPOptions{}
	msgTypeOption := layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeNak)})
	dhcpOptions = append(dhcpOptions, msgTypeOption)

	var flags uint16 = 0x8000

	dhcpLayer := &layers.DHCPv4{
		Operation:    layers.DHCPOpReply, // Type of Bootp reply, always reply when coming from server
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  requestDhcpLayer.HardwareLen,
		HardwareOpts: requestDhcpLayer.HardwareOpts, 
		Flags:		  flags,
		Xid:          requestDhcpLayer.Xid, 
		Secs:         requestDhcpLayer.Secs, 
		YourClientIP: net.IP{0, 0, 0, 0},
		ClientHWAddr: requestDhcpLayer.ClientHWAddr,
		Options:     dhcpOptions,
	}

	return dhcpLayer, nil
}

func (s *Server) readRequestList(layer *layers.DHCPv4, msgType layers.DHCPMsgType) (*layers.DHCPOptions, bool) {
	// Get RequestParams Option from layer.Options
	requestList, ok := dhcpUtils.GetDHCPOption(layer.Options, layers.DHCPOptParamsRequest)
	if !ok {
		return nil, false
	}

	dhcpOptions := layers.DHCPOptions{}
	
	msgTypeOption := layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(msgType)})
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

func (s *Server) buildStdPacket(dstIP net.IP, dstMAC net.HardwareAddr, dhcpLayer *layers.DHCPv4) (*gopacket.SerializeBuffer, error) {
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

func (s *Server) createOffer(dhcpLayer *layers.DHCPv4) error {
	clientMAC := dhcpLayer.ClientHWAddr

	// Checks wether the addr exists, expired or not
	offeredIP := database.IsMACLeased(s.db, clientMAC)
	if offeredIP != nil {
		slog.Debug("MAC is already leased, offering old addr", "oldip", offeredIP.String())
	} else {
		requestedIP, ok := dhcpUtils.GetDHCPOption(dhcpLayer.Options, layers.DHCPOptRequestIP)
		if ok && database.IsIPAvailable(s.db, requestedIP.Data) && !s.IsOccupiedStatic(requestedIP.Data) {
			slog.Debug("Using requested IP from Discover", "ip", requestedIP.Data)
			offeredIP = requestedIP.Data
		} else {
			var err error
			offeredIP, err = s.GenerateIP(s.db, &s.config)
			if err != nil {
				return fmt.Errorf("Failed to generate IP: %w", err)
			}
			slog.Debug("Generated new IP", "ip", offeredIP)
		}
	}

	offerLayer, err := s.constructOfferLayer(dhcpLayer, offeredIP)
	if err != nil {
		return err
	}
	packetPtr, err := s.buildStdPacket(offeredIP, clientMAC, offerLayer)
	if err != nil {
		return err
	}

	slog.Info("Offering Ip to client", "ip", offeredIP, "mac", clientMAC.String())
	s.sendch <- (*packetPtr).Bytes()

	return nil 
}

func (s *Server) constructOfferLayer(discoverLayer *layers.DHCPv4, offeredIP net.IP) (*layers.DHCPv4, error) {
	dhcpOptions, ok := s.readRequestList(discoverLayer, layers.DHCPMsgTypeOffer)
	if !ok {
		slog.Warn("Request list does not exist in Discover")
	}

	dhcpLayer := &layers.DHCPv4{
		Operation:    layers.DHCPOpReply, // Type of Bootp reply, always reply when coming from server
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  discoverLayer.HardwareLen,
		HardwareOpts: discoverLayer.HardwareOpts, 
		Xid:          discoverLayer.Xid, // Need this from discover
		Secs:         discoverLayer.Secs, // Make this up for now
		Flags:		  discoverLayer.Flags,
		YourClientIP: offeredIP, // Your IP is what is offered, what is 'yours'
		ClientHWAddr: discoverLayer.ClientHWAddr,
		Options:     *dhcpOptions,
	}

	return dhcpLayer, nil
}

func (s *Server) processRequest(dhcpLayer *layers.DHCPv4) error {





	clientMAC := dhcpLayer.ClientHWAddr

	// Checks wether the addr exists, expired or not
	offeredIP := database.IsMACLeased(s.db, clientMAC)
	if offeredIP != nil {
		slog.Debug("MAC is already leased, offering old addr", "oldip", offeredIP.String())
	} else {
		requestedIP, ok := dhcpUtils.GetDHCPOption(dhcpLayer.Options, layers.DHCPOptRequestIP)
		if ok && database.IsIPAvailable(s.db, requestedIP.Data) && !s.IsOccupiedStatic(requestedIP.Data) {
			slog.Debug("Using requested IP from Discover", "ip", requestedIP.Data)
			offeredIP = requestedIP.Data
		} else {
			var err error
			offeredIP, err = s.GenerateIP(s.db, &s.config)
			if err != nil {
				return fmt.Errorf("Failed to generate IP: %w", err)
			}
			slog.Debug("Generated new IP", "ip", offeredIP)
		}
	}

	offerLayer, err := s.constructOfferLayer(dhcpLayer, offeredIP)
	if err != nil {
		return err
	}
	packetPtr, err := s.buildStdPacket(offeredIP, clientMAC, offerLayer)
	if err != nil {
		return err
	}

	slog.Info("Offering Ip to client", "ip", offeredIP, "mac", clientMAC.String())
	s.sendch <- (*packetPtr).Bytes()

	return nil 





	clientMAC := dhcpLayer.ClientHWAddr

	var requestedIP net.IP
	requestedIPOpt, ok := dhcpUtils.GetDHCPOption(dhcpLayer.Options, layers.DHCPOptRequestIP)
	if !ok {
		slog.Info("Attempted to get requested IP from request, didn't find it, skipping")
		requestedIP = dhcpLayer.ClientIP
	} else {
		requestedIP = requestedIPOpt.Data
		oldIP := database.IsMACLeased(s.db, clientMAC)
		slog.Debug(fmt.Sprintf("Old IP: %v, %v", oldIP.String(), requestedIP.String()))
		// If not true, usually meanse requested ip is not one in db, need to flush mac
		if slices.Compare(oldIP.To4(), requestedIP.To4()) == 0 {
			slog.Debug("Mac is leased and it is leased to the requested IP, renewing...")
			// Renew the ip lease
			err := database.LeaseIP(s.db, requestedIP, clientMAC, s.config.DHCP.LeaseLen); if err != nil {
				return fmt.Errorf("Unable to renew lease for requested IP: %w\n", err)
			}
		} else if oldIP != nil {
			slog.Debug("Looks like requested IP is different than the stored one, flushing mac")
			err := database.UnleaseMAC(s.db, clientMAC) 
			if err != nil {
				return fmt.Errorf("Error configuring mac for leasing: %v", err)
			}
		} else if database.IsIPAvailable(s.db, requestedIP) {
			slog.Debug(fmt.Sprintf("Looks like its available, using it: %v\n", requestedIP))
			err := database.LeaseIP(s.db, requestedIP, clientMAC, s.config.DHCP.LeaseLen); if err != nil {
				return fmt.Errorf("Unable to create lease for requested IP: %w\n", err)
			}
		} else {
			slog.Debug("Requested IP is not available, sending Nack")
			err := s.createNack(dhcpLayer); if err != nil {
				return fmt.Errorf("Error sending nack in response to request")
			}
			return nil
		}
	}
	ackLayer, err := s.constructAckLayer(dhcpLayer, requestedIP); if err != nil {
		return err
	}
	packetPtr, err := s.buildStdPacket(requestedIP, clientMAC, ackLayer); if err != nil {
		return err
	}
	packetBuf := *packetPtr

	slog.Info(fmt.Sprintf("Acking to Ip: %v", requestedIP.String()))
	s.sendch <- packetBuf.Bytes()

	return nil 
}

func (s *Server) constructAckLayer(requestLayer *layers.DHCPv4, offeredIP net.IP) (*layers.DHCPv4, error) {
	dhcpOptions, ok := s.readRequestList(requestLayer, layers.DHCPMsgTypeAck)
	if !ok {
		slog.Warn("Request list does not exist in request")
	}

	// var flags uint16 = 0x8000

	dhcpLayer := &layers.DHCPv4{
		Operation:    layers.DHCPOpReply, // Type of Bootp reply, always reply when coming from server
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  requestLayer.HardwareLen,
		HardwareOpts: requestLayer.HardwareOpts, 
		Xid:          requestLayer.Xid, // Need this from discover
		Secs:         requestLayer.Secs, // Make this up for now
		Flags:		  requestLayer.Flags,
		YourClientIP: offeredIP, // Your IP is what is offered, what is 'yours'
		ClientHWAddr: requestLayer.ClientHWAddr,
		Options:     *dhcpOptions,
	}

	return dhcpLayer, nil
}

func (s *Server) processDecline(dhcpLayer *layers.DHCPv4) error {
	slog.Info("Recieved Decline, as of right now the server does nothing about this...")
	return nil
}

func (s *Server) processInform(dhcpLayer *layers.DHCPv4) error {
	// err := s.
	return nil
}

func (s *Server) constructInformLayer(requestLayer *layers.DHCPv4, offeredIP net.IP) (*layers.DHCPv4, error) {
	dhcpOptions, ok := s.readRequestList(requestLayer, layers.DHCPMsgTypeInform)
	if !ok {
		slog.Warn("Request list does not exist in inform")
	}

	// var flags uint16 = 0x8000

	dhcpLayer := &layers.DHCPv4{
		Operation:    layers.DHCPOpReply, // Type of Bootp reply, always reply when coming from server
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  requestLayer.HardwareLen,
		HardwareOpts: requestLayer.HardwareOpts, 
		Xid:          requestLayer.Xid, // Need this from discover
		Secs:         requestLayer.Secs, // Make this up for now
		Flags:		  requestLayer.Flags,
		YourClientIP: offeredIP, // Your IP is what is offered, what is 'yours'
		ClientHWAddr: requestLayer.ClientHWAddr,
		Options:     *dhcpOptions,
	}

	return dhcpLayer, nil
}

func (s *Server) sendARPRequest(srcMAC net.HardwareAddr, srcIP, dstIP net.IP) {
	ethLayer := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arpLayer := &layers.ARP{
		AddrType:		   layers.LinkTypeEthernet,
		Protocol:		   layers.EthernetTypeIPv4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Unknown 
		DstProtAddress:    dstIP.To4(),
		HwAddressSize:     6,
		ProtAddressSize:   4,
	}

	// Serialize the layers into a byte buffer
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts, ethLayer, arpLayer)

	slog.Info(fmt.Sprintf("Sending arp request to IP: %v", dstIP.String()))
	s.sendch <- buf.Bytes()

	return
}

func (s *Server) IsOccupiedStatic(targetIP net.IP) bool {
	// Send the ARP request
	s.sendARPRequest(s.serverMAC, s.serverIP, targetIP)

	// Use a timeout mechanism (1 second) with time.After
	timeout := time.After(1 * time.Second)

	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())

	for {
		select {
		case <-timeout:
			slog.Debug("Timeout reached, stopping waiting for ARP reply..")
			return false

		default:
			packet, err := packetSource.NextPacket() // Get the next packet
			if err != nil {
				slog.Error("Error reading arp packet", "error", err)
				continue
			}

			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer != nil {
				arp := arpLayer.(*layers.ARP)

				if arp.Operation == layers.ARPReply && net.IP(arp.SourceProtAddress).Equal(targetIP) {
					slog.Debug(fmt.Sprintf("Received ARP reply from %v: MAC %v", targetIP, net.HardwareAddr(arp.SourceHwAddress)))
					return true
				}
			}
		}
	}
}


// Where we left off
// Upon wanting ip
// Search through all a vailable IPs to check if they have static clients
// When checking. open new gorout
// Have one channel that will end all children when set
// This channel represents the first IP a goroutine finfs is completely available
// Should I really do a worker pool?
// Maybe I make the buffer half the size of the worker pool so I dont hog all workers

// HYPE HYPE HYPE DONT BE LAZY