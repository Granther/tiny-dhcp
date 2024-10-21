package server

import (
	"fmt"
	"log/slog"
	"net"

	// "slices"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	database "gdhcp/database"
	dhcpUtils "gdhcp/dhcp"
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
		return net.HardwareAddr{}, false, fmt.Errorf("error processing mac addr")
	}
}

func extractMAC(dhcpLayer *layers.DHCPv4) (net.HardwareAddr, error) {
	clientMAC, ok := dhcpUtils.GetDHCPOption(dhcpLayer.Options, layers.DHCPOptClientID)
	if !ok {
		return nil, fmt.Errorf("unable to get client mac from dhcp layer")
	}

	mac, _, err := processMAC(net.HardwareAddr(clientMAC.Data))
	if err != nil {
		return nil, fmt.Errorf("error processing mac to usable form: %v", err)
	}

	return mac, nil
}

func (s *Server) createNack(dhcpLayer *layers.DHCPv4) error {
	clientMAC := dhcpLayer.ClientHWAddr

	nackLayer, err := s.constructNackLayer(dhcpLayer)
	if err != nil {
		return err
	}

	broadcastAddr := net.IP{255, 255, 255, 255}
	packetPtr, err := s.buildStdPacket(broadcastAddr, clientMAC, nackLayer)
	if err != nil {
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
		Flags:        flags,
		Xid:          requestDhcpLayer.Xid,
		Secs:         requestDhcpLayer.Secs,
		YourClientIP: net.IP{0, 0, 0, 0},
		ClientHWAddr: requestDhcpLayer.ClientHWAddr,
		Options:      dhcpOptions,
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

	dhcpOptions = append(dhcpOptions, dhcpLeaseTime)
	dhcpOptions = append(dhcpOptions, dhcpServerIP)
	dhcpOptions = append(dhcpOptions, endOptions)

	return &dhcpOptions, true
}

func (s *Server) buildStdPacket(dstIP net.IP, dstMAC net.HardwareAddr, dhcpLayer *layers.DHCPv4) (*gopacket.SerializeBuffer, error) {
	buf := gopacket.NewSerializeBuffer()
	var layersToSerialize []gopacket.SerializableLayer

	ethernetLayer := &layers.Ethernet{
		SrcMAC:       s.serverMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	layersToSerialize = append(layersToSerialize, ethernetLayer)

	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    s.serverIP, // We always respond on the DHCP ip
		DstIP:    dstIP,      // We set the Dest to that of the offered IP
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
				return fmt.Errorf("failed to generate ip: %w", err)
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

	s.cache.PacketCache.Set(string(dhcpLayer.Xid), offerLayer)
	slog.Info("Offering Ip to client", "ip", offeredIP, "mac", clientMAC.String())
	s.sendch <- (*packetPtr).Bytes()

	return nil
}

func (s *Server) constructOfferLayer(discoverLayer *layers.DHCPv4, offeredIP net.IP) (*layers.DHCPv4, error) {
	dhcpOptions, ok := s.readRequestList(discoverLayer, layers.DHCPMsgTypeOffer)
	if !ok {
		slog.Warn("Request list does not exist in Discover")
	}

	// Set flags to unicast, always talk to one host
	var flags uint16 = 0x0000

	dhcpLayer := &layers.DHCPv4{
		Operation:    layers.DHCPOpReply, // Type of Bootp reply, always reply when coming from server
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  discoverLayer.HardwareLen,
		HardwareOpts: discoverLayer.HardwareOpts,
		Xid:          discoverLayer.Xid,  // Need this from discover
		Secs:         discoverLayer.Secs, // Make this up for now
		Flags:        flags,
		YourClientIP: offeredIP, // Your IP is what is offered, what is 'yours'
		ClientHWAddr: discoverLayer.ClientHWAddr,
		Options:      *dhcpOptions,
	}

	return dhcpLayer, nil
}

func (s *Server) getRequestType(dhcpLayer *layers.DHCPv4) (string, error) {
	prevPacket := s.cache.PacketCache.Get(string(dhcpLayer.Xid))

	requestedIPOpt, requestedOpOk := dhcpUtils.GetDHCPOption(dhcpLayer.Options, layers.DHCPOptRequestIP)
	serverIdentOpt, serverIdOpOk := dhcpUtils.GetDHCPOption(dhcpLayer.Options, layers.DHCPOptServerID)

	if prevPacket != nil {
		if serverIdOpOk && requestedOpOk && net.IP(serverIdentOpt.Data).Equal(s.serverIP) && dhcpLayer.ClientIP.Equal(net.IP{0, 0, 0, 0}) && prevPacket.YourClientIP.Equal(net.IP(requestedIPOpt.Data)) {
			return "selecting", nil
		}
	} else if !serverIdOpOk && requestedOpOk && dhcpLayer.ClientIP.Equal(net.IP{0, 0, 0, 0}) {
		return "init", nil
	} else if !serverIdOpOk && !requestedOpOk && !dhcpLayer.ClientIP.Equal(net.IP{0, 0, 0, 0}) {
		return "renewing", nil
	} else {
		return "none", nil
	}

	slog.Debug("Reached none request type", "serverIdOptOk", serverIdOpOk, "requestedOpOk", requestedOpOk, "dhcpLayer.ClientIP", dhcpLayer.ClientIP.String())
	return "none", nil
}

func (s *Server) processRequest(dhcpLayer *layers.DHCPv4) error {

	requestType, err := s.getRequestType(dhcpLayer)
	if err != nil {
		return err
	}

	slog.Debug("Request type", "type", requestType)

	// selecting if
	// contains server ident of this server
	// client addr 0.0.0.0
	// requested IP is offered IP from offer packet

	// init if
	// no server ident
	// requeted ip is filled/
	// client add must be 0.0.0.0
	// Send nack to client if requested IP is not the one in the lease book
	// or if it is on the wrong net
	// If server has no idea who this guy is, stay quiet (may be another server's client)

	// renwing
	// no server ident
	// no requested ip/
	// cleint addr must be actual ip addr
	// will be unicast from client

	// rebinding
	// no server ident
	// no requested ip opt
	// client addr is leased addr
	// this request will be broadcast from client

	// Cache methods
	// IsIPAvailable
	// lease ip
	// is mac leases
	//

	// We dont know what to do
	// If i check inf an ip is available, should I do an arp every time?
	// init
	// When generating we have to arp, so dont do it again
	// When initing, we shouldnt have unleases ip even if expired
	// Arp should only happen when generating

	clientMAC := dhcpLayer.ClientHWAddr
	requestedIP := net.IP{0, 0, 0, 0}

	if requestType == "selecting" {
		requestedIPOpt, ok := dhcpUtils.GetDHCPOption(dhcpLayer.Options, layers.DHCPOptRequestIP)
		if ok && s.cache.IsIPAvailable(requestedIPOpt.Data) {
			// Remove from Queue
			s.cache.AddrQueue.deQueue()

			slog.Debug(fmt.Sprintf("Looks like its available, using it: %v\n", requestedIPOpt.Data))
			err := s.cache.LeaseIP(requestedIPOpt.Data, clientMAC, s.config.DHCP.LeaseLen)
			if err != nil {
				return fmt.Errorf("unable to create lease for requested ip: %w", err)
			}
			requestedIP = requestedIPOpt.Data
		} else {
			goto NACK
		}
	} else if requestType == "init" {
		oldIP := s.cache.IsMACLeased(clientMAC)
		requestedIPOpt, ok := dhcpUtils.GetDHCPOption(dhcpLayer.Options, layers.DHCPOptRequestIP)

		slog.Debug("Request Init", "OldIP", oldIP.String(), "Reqip", net.IP(requestedIPOpt.Data).String())

		if oldIP != nil && ok {
			if oldIP.Equal(net.IP(requestedIPOpt.Data)) {
				slog.Debug("Mac is assigned to requested ip")
				requestedIP = oldIP
			} else {
				slog.Debug("oldIP does not equal requested ip", "requestedIP", requestedIP.String())
				goto NACK
			}
		} else {
			slog.Debug("Requested IP is not available, sending Nack")
			goto NACK
		}
	} else if requestType == "renewing" {
		currentIP := s.cache.IsMACLeased(clientMAC)
		if currentIP != nil {
			// if dhcpLayer.ClientIP.Equal(currentIP) {
			// slog.Debug("Mac is assigned to current ip, renewing")
			// Renew the ip lease
			slog.Debug("CurrentIP isnt nil, renewing...")
			err := s.cache.LeaseIP(requestedIP, clientMAC, s.config.DHCP.LeaseLen)
			if err != nil {
				return fmt.Errorf("unable to renew lease for requested ip: %w", err)
			}
			requestedIP = currentIP
		} else {
			slog.Debug("Client is trying to renew, but it not know by this server, sending NACK")
			err := s.createNack(dhcpLayer)
			if err != nil {
				return fmt.Errorf("error sending nack in response to request")
			}
			return nil
		}
	} else {
		slog.Warn("Request type did not fit, dropping packet")
		return nil
	}

	NACK:
		slog.Debug("Requested IP is not available, sending Nack")
		err = s.createNack(dhcpLayer)
		if err != nil {
			return fmt.Errorf("error sending nack in response to request")
		}
		return nil

	if requestedIP.Equal(net.IP{0, 0, 0, 0}) {
		slog.Debug("Requested IP set to 0.0.0.0")
	}

	ackLayer, err := s.constructAckLayer(dhcpLayer, requestedIP)
	if err != nil {
		return err
	}
	packetPtr, err := s.buildStdPacket(requestedIP, clientMAC, ackLayer)
	if err != nil {
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
		Xid:          requestLayer.Xid,  // Need this from discover
		Secs:         requestLayer.Secs, // Make this up for now
		Flags:        requestLayer.Flags,
		YourClientIP: offeredIP, // Your IP is what is offered, what is 'yours'
		ClientHWAddr: requestLayer.ClientHWAddr,
		Options:      *dhcpOptions,
	}

	return dhcpLayer, nil
}

func (s *Server) processDecline(dhcpLayer *layers.DHCPv4) error {
	slog.Info("Recieved Decline, as of right now the server does nothing about this...")
	return nil
}

func (s *Server) processInform(dhcpLayer *layers.DHCPv4) error {
	clientMAC := dhcpLayer.ClientHWAddr
	if clientMAC == nil {
		return fmt.Errorf("client mac nil in dhcp inform")
	}

	clientIP := dhcpLayer.ClientIP
	if clientIP == nil {
		return fmt.Errorf("client ip nil in dhcp inform")
	}

	ackLayer, err := s.constructAckLayer(dhcpLayer, clientIP)
	if err != nil {
		return err
	}
	packetPtr, err := s.buildStdPacket(clientIP, clientMAC, ackLayer)
	if err != nil {
		return err
	}
	packetBuf := *packetPtr

	slog.Info(fmt.Sprintf("Acking inform to Ip: %v", clientIP.String()))
	s.sendch <- packetBuf.Bytes()

	return nil
}

// Attempts to release by MAC, then tries by IP
func (s *Server) processRelease(dhcpLayer *layers.DHCPv4) error {
	clientMAC := dhcpLayer.ClientHWAddr
	if clientMAC != nil {
		s.cache.UnleaseMAC(clientMAC)
		return nil
	}

	clientIP := dhcpLayer.ClientIP
	if clientIP != nil {
		s.cache.UnleaseIP(clientIP)
		return nil
	}

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
		Xid:          requestLayer.Xid,  // Need this from discover
		Secs:         requestLayer.Secs, // Make this up for now
		Flags:        requestLayer.Flags,
		YourClientIP: offeredIP, // Your IP is what is offered, what is 'yours'
		ClientHWAddr: requestLayer.ClientHWAddr,
		Options:      *dhcpOptions,
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
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
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

// HYPE HYPE HYPE DONT BE LAZY
