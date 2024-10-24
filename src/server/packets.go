package server

import (
	"fmt"
	"gdhcp/utils"
	"log/slog"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func (s *Server) buildStdPacket(dstIP net.IP, dstMAC net.HardwareAddr, dhcpLayer *layers.DHCPv4) (*gopacket.SerializeBuffer, error) {
	serverIP := s.network.ServerIP()
	serverMac := s.network.ServerMac()

	buf := gopacket.NewSerializeBuffer()
	var layersToSerialize []gopacket.SerializableLayer

	ethernetLayer := &layers.Ethernet{
		SrcMAC:       serverMac,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	layersToSerialize = append(layersToSerialize, ethernetLayer)

	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    serverIP, // We always respond on the DHCP ip
		DstIP:    dstIP,    // We set the Dest to that of the offered IP
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

	slog.Info("Sending nak to client mac", "mac", clientMAC.String())
	s.network.SubmitBytes(packetBuf.Bytes())

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

func (s *Server) createOffer(dhcpLayer *layers.DHCPv4) error {
	clientMAC := dhcpLayer.ClientHWAddr

	// Checks wether the addr exists, expired or not
	offeredIP := s.lease.IsMACLeased(clientMAC)
	if offeredIP != nil {
		slog.Debug("MAC is already leased, offering old addr", "ip", offeredIP.String())
	} else {
		requestedIP, ok := utils.GetDHCPOption(&dhcpLayer.Options, layers.DHCPOptRequestIP)
		if ok && s.lease.IsIPAvailable(requestedIP.Data) && !s.IsOccupiedStatic(requestedIP.Data) {
			slog.Debug("Using requested IP from Discover", "ip", requestedIP.Data)
			offeredIP = requestedIP.Data
		} else {
			var err error
			offeredIP, err = s.GenerateIP()
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

	s.packet.Set(string(dhcpLayer.Xid), offerLayer)
	slog.Info("Offering Ip to client", "ip", offeredIP, "mac", clientMAC.String())
	s.network.SubmitBytes((*packetPtr).Bytes())

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
