package server

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"gdhcp/utils"
)

func (s *Server) readRequestList(layer *layers.DHCPv4, msgType layers.DHCPMsgType) (*layers.DHCPOptions, bool) {
	// Get RequestParams Option from layer.Options
	requestList, ok := utils.GetDHCPOption(&layer.Options, layers.DHCPOptParamsRequest)
	if !ok {
		return nil, false
	}

	dhcpOptions := layers.DHCPOptions{}

	msgTypeOption := layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(msgType)})
	dhcpOptions = append(dhcpOptions, msgTypeOption)
	// Iterate over Request List, get option requested
	for _, req := range requestList.Data {
		val, ok := s.options.Get(layers.DHCPOpt(req))
		if !ok { // Option value does not exist, server cannot fufill
			continue
		}

		op := layers.NewDHCPOption(layers.DHCPOpt(req), val.ToBytes())
		dhcpOptions = append(dhcpOptions, op)
	}

	leaseLen, ok := s.options.Get(layers.DHCPOptLeaseTime)
	if !ok {
		return nil, false
	}

	dhcpLeaseTime := layers.NewDHCPOption(layers.DHCPOptLeaseTime, leaseLen.ToBytes())
	dhcpServerIP := layers.NewDHCPOption(layers.DHCPOptServerID, s.network.ServerIP().To4())
	endOptions := layers.NewDHCPOption(layers.DHCPOptEnd, []byte{})

	dhcpOptions = append(dhcpOptions, dhcpLeaseTime)
	dhcpOptions = append(dhcpOptions, dhcpServerIP)
	dhcpOptions = append(dhcpOptions, endOptions)

	return &dhcpOptions, true
}

func (s *Server) processRequest(dhcpLayer *layers.DHCPv4) error {

	requestType, err := s.getRequestType(dhcpLayer)
	if err != nil {
		return err
	}

	slog.Debug("Request type", "type", requestType)

	clientMAC := dhcpLayer.ClientHWAddr
	requestedIP := net.IP{0, 0, 0, 0}

	if requestType == "selecting" {
		requestedIPOpt, ok := utils.GetDHCPOption(&dhcpLayer.Options, layers.DHCPOptRequestIP)
		if ok && s.lease.IsIPAvailable(requestedIPOpt.Data) {
			// Remove from Queue
			s.addr.DeQueue()

			slog.Debug(fmt.Sprintf("Looks like its available, using it: %v\n", requestedIPOpt.Data))
			err := s.lease.LeaseIP(requestedIPOpt.Data, clientMAC, s.config.DHCP.LeaseLen)
			if err != nil {
				return fmt.Errorf("unable to create lease for requested ip: %w", err)
			}
			requestedIP = requestedIPOpt.Data
		} else {
			goto NACK
		}
	} else if requestType == "init" {
		oldIP := s.lease.IsMACLeased(clientMAC)
		requestedIPOpt, ok := utils.GetDHCPOption(&dhcpLayer.Options, layers.DHCPOptRequestIP)

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
		currentIP := s.lease.IsMACLeased(clientMAC)
		if currentIP != nil {
			// if dhcpLayer.ClientIP.Equal(currentIP) {
			// slog.Debug("Mac is assigned to current ip, renewing")
			// Renew the ip lease
			slog.Debug("CurrentIP isnt nil, renewing...")
			err := s.lease.LeaseIP(requestedIP, clientMAC, s.config.DHCP.LeaseLen)
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

	if requestedIP.Equal(net.IP{0, 0, 0, 0}) {
		slog.Debug("Requested IP set to 0.0.0.0")
	}

	NACK:
		slog.Debug("Requested IP is not available, sending Nack")
		err = s.createNack(dhcpLayer)
		if err != nil {
			return fmt.Errorf("error sending nack in response to request")
		}
		return nil

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
	s.network.SubmitBytes(packetBuf.Bytes())

	return nil
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
	s.network.SubmitBytes(packetBuf.Bytes())

	return nil
}

// Attempts to release by MAC, then tries by IP
func (s *Server) processRelease(dhcpLayer *layers.DHCPv4) error {
	clientMAC := dhcpLayer.ClientHWAddr
	if clientMAC != nil {
		s.lease.UnleaseMAC(clientMAC)
		return nil
	}

	clientIP := dhcpLayer.ClientIP
	if clientIP != nil {
		s.lease.UnleaseIP(clientIP)
		return nil
	}

	return nil
}

func (s *Server) sendARPRequest(dstIP net.IP) {
	serverMac := s.network.ServerMac()
	serverIP := s.network.ServerIP()

	ethLayer := &layers.Ethernet{
		SrcMAC:       serverMac,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   serverMac,
		SourceProtAddress: serverIP.To4(),
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
	s.network.SubmitBytes(buf.Bytes())
}

func (s *Server) getRequestType(dhcpLayer *layers.DHCPv4) (string, error) {
	prevPacket := s.packet.Get(string(dhcpLayer.Xid))

	requestedIPOpt, requestedOpOk := utils.GetDHCPOption(&dhcpLayer.Options, layers.DHCPOptRequestIP)
	serverIdentOpt, serverIdOpOk := utils.GetDHCPOption(&dhcpLayer.Options, layers.DHCPOptServerID)

	if prevPacket != nil {
		if serverIdOpOk && requestedOpOk && net.IP(serverIdentOpt.Data).Equal(s.network.ServerIP()) && dhcpLayer.ClientIP.Equal(net.IP{0, 0, 0, 0}) && prevPacket.YourClientIP.Equal(net.IP(requestedIPOpt.Data)) {
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