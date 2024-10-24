package server

import (
	"fmt"
	"log"
	"log/slog"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"gdhcp/cache"
	"gdhcp/config"
	"gdhcp/database"
	"gdhcp/network"
	"gdhcp/options"
	"gdhcp/utils"
	"gdhcp/worker"
)

type Server struct {
	config     *config.Config
	storage    database.PersistentHandler
	network    network.NetworkHandler
	lease      cache.LeaseCacheHandler
	addr       cache.AddrQueueHandler
	packet     cache.PacketHandler
	options    options.OptionsHandler
	workerPool worker.WorkerPoolHandler
	quitch     chan struct{}
}

func NewServer(serverConfig *config.Config) (*Server, error) {
	// Worker layer, where processing is done
	workerPool := worker.NewWorkerPool(serverConfig.Server.NumWorkers)

	// Network layer, where the network is listened to
	network, err := network.NewNetworkManager(workerPool, serverConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create network module for server instantiation: %w", err)
	}

	// Storage layer, where external persistent data is stored
	storage := database.NewSQLiteManager()

	packet := cache.NewPacketCache(20, 20)
	lease := cache.NewLeaseCache(storage)
	addr := cache.NewAddrQueue(20, serverConfig.DHCP.AddrPool, lease)

	options := options.NewOptionsManager(serverConfig)

	server := &Server{
		config:     serverConfig,
		workerPool: workerPool,
		network:    network,
		packet:     packet,
		lease:      lease,
		addr:       addr,
		storage:    storage,
		options:    options,
	}

	return server, nil
}

func (s *Server) Start() error {
	slog.Info("Starting server...")

	// Start all worker goroutes
	s.workerPool.StartWorkers()

	// Ensure a storage connection can be made
	s.storage.Connect()

	// Fill lease in-memory data
	s.lease.ReadLeasesFromPersistent()
	s.addr.FillQueue()
	s.packet.CleanJob(15)

	// Create options map
	s.options.Create()

	// Begin listening for new jobs
	// Do this last as we MUST be ready
	go s.network.ReceivePackets(s.HandleDHCPPacket)
	go s.network.SendPackets()

	slog.Info("Server is now listening for packets/quitch")

	// Wait for quit signal is recieved on this channel
	<-s.quitch

	// Close connection and channels
	s.workerPool.Stop()
	s.network.Close()

	return nil
}

// Function to handle a DHCP packet in a new goroutine
func (s *Server) HandleDHCPPacket(packetSlice []byte) error {
	dhcpLayer, ok := gopacket.NewPacket(packetSlice, layers.LayerTypeDHCPv4, gopacket.Default).Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4)
	if !ok {
		return fmt.Errorf("error getting dhcp layer from packet")
	}

	switch message, _ := utils.GetMessageTypeOption(&dhcpLayer.Options); message {
	case layers.DHCPMsgTypeDiscover:
		slog.Debug("Got Discover")
		err := s.createOffer(dhcpLayer)
		if err != nil {
			return fmt.Errorf("error creating offer: %v", err)
		}
	case layers.DHCPMsgTypeRequest:
		slog.Debug("Got Request")
		err := s.processRequest(dhcpLayer)
		if err != nil {
			return fmt.Errorf("error processing request: %v", err)
		}
	case layers.DHCPMsgTypeDecline:
		slog.Debug("Got Decline")
		err := s.processDecline(dhcpLayer)
		if err != nil {
			return fmt.Errorf("error processing decline: %v", err)
		}
	case layers.DHCPMsgTypeInform:
		slog.Debug("Got Inform")
		err := s.processInform(dhcpLayer)
		if err != nil {
			return fmt.Errorf("error processing inform: %v", err)
		}
	case layers.DHCPMsgTypeRelease:
		slog.Debug("Got Release")
		err := s.processRelease(dhcpLayer)
		if err != nil {
			return fmt.Errorf("error processing release: %v", err)
		}
	case layers.DHCPMsgTypeOffer:
		slog.Debug("Got Offer")
	case layers.DHCPMsgTypeAck:
		log.Printf("Got Ack")
	case layers.DHCPMsgTypeNak:
		log.Printf("Got Nak")
	case layers.DHCPMsgTypeUnspecified:
		log.Printf("Error, DHCP operation type is unspecified")
	}

	return nil
}
