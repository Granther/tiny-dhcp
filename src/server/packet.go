package server

import "gdhcp/config"

type PacketHandler interface {
	HandleDHCPPacket(data []byte) error
}

type PacketManager struct {
	workerPool chan struct{}
}

func NewPacketManager(network NetworkHandler, config *config.Config) (PacketHandler, error) {
	return &PacketManager{}, nil
}

func (p *PacketManager) HandleDHCPPacket(data []byte) error {
	return nil
}

