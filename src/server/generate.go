package server

import (
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func (s *Server) IsOccupiedStatic(targetIP net.IP) bool {
	// Send the ARP request
	s.sendARPRequest(targetIP)

	// Use a timeout mechanism (1 second) with time.After
	timeout := time.After(1 * time.Second)

	handle := s.network.Handle()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

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

func (s *Server) GenerateIP() (net.IP, error) {
	ip := s.addr.Front()         // Moves top addr to end
	if !s.IsOccupiedStatic(ip) { // Not a static
		return ip, nil
	}
	return nil, fmt.Errorf("unable to generate ip addr, pool full?")
}
