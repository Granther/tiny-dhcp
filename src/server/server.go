package server

import (
	"database/sql"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"gdhcp/cache"
	"gdhcp/config"
	"gdhcp/database"
	"gdhcp/options"
	"gdhcp/utils"
)

type Server struct {
	conn      *net.UDPConn
	handle    *pcap.Handle
	serverIP  net.IP
	serverMAC net.HardwareAddr
	config    config.Config

	optionsMap map[layers.DHCPOpt]options.DHCPOptionValue
	db         *sql.DB
	cache      *cache.Cache

	workerPool chan struct{}
	packetch   chan packetJob
	ipch       chan net.IP
	sendch     chan []byte
	quitch     chan struct{}

	NetworkManager *NetworkManager
}

type packetJob struct {
	data       []byte
	clientAddr *net.UDPAddr
}

func NewServer(config config.Config) (*Server, error) {
	iface, err := net.InterfaceByName(config.Server.ListenInterface)
	if err != nil {
		slog.Error(fmt.Sprintf("failed to get interface: %v", err))
		os.Exit(1)
	}

	serverIP, err := utils.GetUDPAddr(iface)
	if err != nil {
		slog.Error(fmt.Sprintf("error occured while creating listen address struct, please review the interface configuration: %v", err))
		os.Exit(1)
	}

	// Listen on all IPs
	listenAddr := net.UDPAddr{IP: net.IP{0, 0, 0, 0}, Port: 67}
	conn, err := net.ListenUDP("udp", &listenAddr)
	if err != nil {
		return nil, fmt.Errorf("error creating server UDP listener: %v", err)
	}

	// handle, err := pcap.OpenLive("\\Device\\NPF_{3C62326A-1389-4DB7-BCF8-55747D0B8757}", 1500, false, pcap.BlockForever)

	// Create handle for responding to requests later on
	handle, err := pcap.OpenLive(iface.Name, 1500, false, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("could not open pcap device: %w", err)
	}

	optionsMap := options.CreateOptionMap(config)
	numWorkers := config.Server.NumWorkers

	db, err := database.ConnectDatabase()
	if err != nil {
		return nil, fmt.Errorf("error occured when connecting to db object: %v", err)
	}

	// packetCache := cache.NewPacketCache(5, 15)
	// addrQueue := cache.NewAddrQueue(30)

	newCache := cache.NewCache(5, 15, 20, 20, config.DHCP.AddrPool, db)
	newCache.Init(db, 20)
	newCache.AddrQueue.PrintQueue()
	newCache.LeasesCache.PrintCache()

	return &Server{
		conn:       conn,
		handle:     handle,
		serverIP:   serverIP.IP,
		serverMAC:  iface.HardwareAddr,
		config:     config,
		optionsMap: optionsMap,
		db:         db,
		cache:      newCache,
		workerPool: make(chan struct{}, numWorkers),
		packetch:   make(chan packetJob, 1000), // Can hold 1000 packets
		ipch:       make(chan net.IP),
		sendch:     make(chan []byte, 1000), // Can hold 1000 queued packets to be sent
		quitch:     make(chan struct{}),
	}, nil
}

func (s *Server) Start() error {
	slog.Info("Starting server...")

	numWorkers := s.config.Server.NumWorkers
	for i := 0; i < numWorkers; i++ {
		go s.worker()
	}

	go s.receivePackets()
	go s.sendPackets()
	go s.cache.PacketCache.CleanJob(15)

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

func (s *Server) receivePackets() {
	go func() {
		for {
			buffer := make([]byte, 4096)
			n, clientAddr, err := s.conn.ReadFromUDP(buffer)
			if err != nil {
				slog.Error(fmt.Sprintf("Error receiving packet: %v", err))
				continue
			}

			select {
			case s.packetch <- packetJob{data: buffer[:n], clientAddr: clientAddr}:
				// Packet added to queue
			default:
				// Queue is full, log and drop packet
				slog.Warn(fmt.Sprintf("Packet queue full, dropping packet from %v", clientAddr))
			}
		}
	}()
}

func (s *Server) sendPackets() {
	// Iterate over sendchannel, send all ready packets
	for packet := range s.sendch {
		err := s.sendPacket(packet)
		if err != nil {
			slog.Debug(fmt.Sprintf("Error occured while sending ready packet: %v", err))
		}
	}
}

func (s *Server) sendPacket(packet []byte) error {
	if err := s.handle.WritePacketData(packet); err != nil {
		return fmt.Errorf("failed to send packet: %w", err)
	}
	return nil
}

func (s *Server) worker() {
	for job := range s.packetch {
		s.workerPool <- struct{}{}
		err := s.handleDHCPPacket(job.data)
		if err != nil {
			slog.Error(fmt.Sprintf("Error occured while handline dhcp packet: %v", err))
		}
		// Reads one item off the worker queue
		<-s.workerPool
	}
}

// Function to handle a DHCP packet in a new goroutine
func (s *Server) handleDHCPPacket(packetSlice []byte) error {
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
