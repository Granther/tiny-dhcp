package server

import (
	"fmt"
	"gdhcp/config"
	"gdhcp/utils"
	"net"

	"github.com/google/gopacket/pcap"
)

// Handles UDP connection and network send/recv
type NetworkManager struct {
	conn     *net.UDPConn
	handle   *pcap.Handle
	serverIP net.IP
	packetch chan packetJob
	sendch   chan []byte
}

// Instantiate new NetworkManager
func NewNetworkManager(config *config.Config) (*NetworkManager, error) {
	iface, err := net.InterfaceByName(config.Server.ListenInterface)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface by name of %s: %w", config.Server.ListenInterface, err)
	}

	serverIP, err := utils.GetInterfaceIP(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to : %w", err)
	}

	// Listen on all IPs
	listenAddr := net.UDPAddr{IP: net.IP{0, 0, 0, 0}, Port: 67}
	conn, err := net.ListenUDP("udp", &listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create server udp listener on 0.0.0.0: %w", err)
	}

	// handle, err := pcap.OpenLive("\\Device\\NPF_{3C62326A-1389-4DB7-BCF8-55747D0B8757}", 1500, false, pcap.BlockForever)
	// Create handle for responding to requests later on
	handle, err := pcap.OpenLive(iface.Name, 1500, false, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("could not open pcap device: %w", err)
	}

	return &NetworkManager{
		conn:     conn,
		handle:   handle,
		serverIP: serverIP,
		packetch: make(chan packetJob, 1000), // Can hold 1000 packets
		sendch:   make(chan []byte, 1000),    // Can hold 1000 queued packets to be sent
	}, nil
}
