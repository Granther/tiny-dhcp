package server

import (
	"fmt"
	"net"
)

type JobHandler interface {
	Process(server *Server) error
}

type PacketJob struct {
	data       []byte
	clientAddr *net.UDPAddr
	server     *Server
}

func (p *PacketJob) Process(server *Server) error {
	err := p.server.HandleDHCPPacket(p.data)
	if err != nil {
		return fmt.Errorf("failure in processing packet data: %w", err)
	}
	return nil
}
