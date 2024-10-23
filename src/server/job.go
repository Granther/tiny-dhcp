package server

import (
	"fmt"
)

type JobHandler interface {
	Process() error
}

type PacketJob struct {
	data   []byte
	server *Server
}

func NewPacketJob(data []byte, server *Server) JobHandler {
	return &PacketJob{
		data:   data,
		server: server,
	}
}

func (p *PacketJob) Process() error {
	err := p.server.HandleDHCPPacket(p.data)
	if err != nil {
		return fmt.Errorf("failure in processing packet data: %w", err)
	}
	return nil
}
