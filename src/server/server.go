package server

import (
	"database/sql"
	"fmt"
	"log"
	"log/slog"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"gdhcp/cache"
	"gdhcp/config"
	"gdhcp/database"
	"gdhcp/options"
	"gdhcp/utils"
)

type Server struct {
	config     *config.Config
	storage    database.PersistentHandler
	network    NetworkHandler
	packet     PacketHandler
	options    options.OptionsHandler
	cache      cache.CacheHandler
	workerPool WorkerPoolHandler
	quitch     chan struct{}
}

func NewServer(serverConfig *config.Config) (*Server, error) {
	workerPool := NewWorkerPool(serverConfig.Server.NumWorkers)

	network, err := NewNetworkManager(serverConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create network module for server instantiation: %w", err)
	}

	packet, err := NewPacketManager(network, serverConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create packet handler module for server instantiation: %w", err)
	}

	storage := database.NewSQLiteManager()
	if err != nil {
		return nil, fmt.Errorf("failed to create storage module for server instantiation: %w", err)
	}

	cache := cache.NewCacheManager(storage, serverConfig)

	options := options.NewOptionsManager(serverConfig)

	server := &Server{
		config:		serverConfig,
		workerPool: workerPool,
		network:    network,
		packet:     packet,
		storage:    storage,
		options:    options,
		cache:      cache,
	}

	return server, nil
}

func (s *Server) Start() error {
	slog.Info("Starting server...")

	// Start all worker goroutes
	s.workerPool.StartWorkers()

	go s.network.ReceivePackets()
	go s.network.SendPackets()
	// go s.cache.PacketCache.CleanJob(15)

	slog.Info("Server is now listening for packets/quitch")

	// Wait for quit signal is recieved on this channel
	<-s.quitch

	// Close connection and channels
	s.conn.Close()
	s.handle.Close()
	close(s.packetch)
	close(s.workerPool)
	close(s.sendch)

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

func (s *Server) GenerateIP(db *sql.DB) (net.IP, error) {
	ip := s.cache.AddrQueue.Front()
	if !s.IsOccupiedStatic(ip) {
		return ip, nil
	}

	return nil, fmt.Errorf("unable to generate ip addr, pool full?")
}

	// packetCache := cache.NewPacketCache(5, 15)
	// addrQueue := cache.NewAddrQueue(30)
	// newCache := cache.NewCache(5, 15, 20, 20, config.DHCP.AddrPool, db)
	// newCache.Init(db, 20)
	// newCache.AddrQueue.PrintQueue()
	// newCache.LeasesCache.PrintCache()

	// return &Server{
	// 	conn:       conn,
	// 	handle:     handle,
	// 	serverIP:   serverIP.IP,
	// 	serverMAC:  iface.HardwareAddr,
	// 	config:     config,
	// 	optionsMap: optionsMap,
	// 	db:         db,
	// 	cache:      newCache,

	// 	network: network,

	// 	workerPool: make(chan struct{}, numWorkers),
	// 	packetch:   make(chan packetJob, 1000), // Can hold 1000 packets
	// 	ipch:       make(chan net.IP),
	// 	sendch:     make(chan []byte, 1000), // Can hold 1000 queued packets to be sent
	// 	quitch:     make(chan struct{}),
	// }, nil