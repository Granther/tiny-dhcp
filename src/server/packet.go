package server

import "gdhcp/config"

type PacketHandler interface {
}

type PacketManager struct {
	workerPool chan struct{}
}

func NewPacketManager(network NetworkHandler, config *config.Config) (PacketHandler, error) {
	return &PacketManager{}, nil
}


