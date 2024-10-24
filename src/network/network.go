package network

import (
	"fmt"
	"gdhcp/config"
	"gdhcp/utils"
	"gdhcp/worker"
	"log/slog"
	"net"

	"github.com/google/gopacket/pcap"
)

type NetworkHandler interface {
	ReceivePackets(jobFunc func([]byte) error)
	SendPackets()
	SendPacket(packet []byte) error
	SubmitBytes(data []byte)
	Conn() *net.UDPConn
	Handle() *pcap.Handle
	ServerIP() net.IP
	ServerMac() net.HardwareAddr
	Close()
}

// Handles UDP connection and network send/recv
type NetworkManager struct {
	conn       *net.UDPConn
	handle     *pcap.Handle
	serverIP   net.IP
	serverMac  net.HardwareAddr
	workerPool worker.WorkerPoolHandler
	packetch   chan worker.PacketJob
	sendch     chan []byte
}

// Instantiate new NetworkManager
func NewNetworkManager(workerPool worker.WorkerPoolHandler, config *config.Config) (NetworkHandler, error) {
	iface, err := net.InterfaceByName(config.Server.ListenInterface)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface by name of %s: %w", config.Server.ListenInterface, err)
	}

	serverIP, err := utils.GetInterfaceIP(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve server ip: %w", err)
	}

	serverMac, err := utils.GetInterfaceMac(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve server mac: %w", err)
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
		conn:       conn,
		handle:     handle,
		serverIP:   serverIP,
		serverMac:  serverMac,
		workerPool: workerPool,
		packetch:   make(chan worker.PacketJob, 1000), // Can hold 1000 packets
		sendch:     make(chan []byte, 1000),           // Can hold 1000 queued packets to be sent
	}, nil
}

func (n *NetworkManager) ReceivePackets(jobFunc func([]byte) error) {
	for {
		buffer := make([]byte, 4096)
		num, _, err := n.conn.ReadFromUDP(buffer)
		if err != nil {
			slog.Error("Failed to read received packet", "error", err)
			continue
		}

		job := worker.NewPacketJob(buffer[:num], jobFunc)
		n.workerPool.SubmitJob(job)

		// select {
		// case n.packetch <- PacketJob{data: buffer[:num], clientAddr: clientAddr, server: server}:
		// 	// Packet added to queue
		// default:
		// 	// Queue is full, log and drop packet
		// 	slog.Warn("Packet queue full, dropping packet", "srcIP", clientAddr)
		// }
	}
}

func (n *NetworkManager) SendPackets() {
	// Iterate over sendchannel, send all ready packets
	for packet := range n.sendch {
		err := n.SendPacket(packet)
		if err != nil {
			slog.Error("Error occured while sending ready packet, continuing...", "error", err)
		}
	}
}

func (n *NetworkManager) SendPacket(packet []byte) error {
	if err := n.handle.WritePacketData(packet); err != nil {
		return fmt.Errorf("failed to send packet: %w", err)
	}
	return nil
}

func (n *NetworkManager) Close() {
	close(n.packetch)
	close(n.sendch)
}

func (n *NetworkManager) SubmitBytes(data []byte) {
	n.sendch <- data
}

func (n *NetworkManager) Conn() *net.UDPConn { return n.conn }

func (n *NetworkManager) Handle() *pcap.Handle { return n.handle }

func (n *NetworkManager) ServerIP() net.IP { return n.serverIP }

func (n *NetworkManager) ServerMac() net.HardwareAddr { return n.serverMac }
