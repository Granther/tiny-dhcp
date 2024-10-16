package server

import (
	"os"
	"net"
	"fmt"
	"log"
	"time"
	"log/slog"
	"database/sql"
	"sync/atomic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"

	c "gdhcp/config"
	dhcpUtils "gdhcp/dhcp"
	deviceUtils "gdhcp/device"
	options "gdhcp/options"
	database "gdhcp/database"
	cache "gdhcp/cache"
)

var globServer atomic.Value

type Server struct {
	conn		*net.UDPConn
	handle		*pcap.Handle
	serverIP	net.IP
	serverMAC	net.HardwareAddr
	config		c.Config
	optionsMap	map[layers.DHCPOpt]options.DHCPOptionValue
	db			*sql.DB
	packetCache	*cache.PacketCache
	workerPool	chan struct{}
	packetch 	chan packetJob
	ipch		chan net.IP
	sendch		chan []byte
	quitch		chan struct{}
}

type packetJob struct {
    data        []byte
    clientAddr  *net.UDPAddr
}

func NewServer(config c.Config) (*Server, error) {
	iface, err := net.InterfaceByName(config.Server.ListenInterface)
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to get interface: %v", err))
		os.Exit(1)
	}

	serverIP, err := deviceUtils.GetUDPAddr(iface)
	if err != nil {
		slog.Error(fmt.Sprintf("Error occured while creating listen address struct, please review the interface configuration: %v\n", err))
		os.Exit(1)
	}
	
	// Listen on all IPs
	listenAddr := net.UDPAddr{IP: net.IP{0, 0, 0, 0},  Port: 67}
	conn, err := net.ListenUDP("udp", &listenAddr)
	if err != nil {
        return nil, fmt.Errorf("Error creating server UDP listener: %v\n", err)
    }

	// WINDOWS DEV
	// Windows interface: \\Device\\NPF_{3C62326A-1389-4DB7-BCF8-55747D0B8757}
	// handle, err := pcap.OpenLive("\\Device\\NPF_{3C62326A-1389-4DB7-BCF8-55747D0B8757}", 1500, false, pcap.BlockForever)

	// Create handle for responding to requests later on
	handle, err := pcap.OpenLive(iface.Name, 1500, false, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("Could not open pcap device: %w\n", err)
	}

	optionsMap := options.CreateOptionMap(config)
	numWorkers := config.Server.NumWorkers

	db, err := database.ConnectDatabase()
	if err != nil {
		return nil, fmt.Errorf("Error occured when connecting to db object: %v\n", err)
	}

	packetCache := cache.NewPacketCache(5, time.Duration(time.Second * 10))

	return &Server{
		conn:			conn,
		handle:			handle,
		serverIP:		serverIP.IP,
		serverMAC:		iface.HardwareAddr,
		config:			config,
		optionsMap: 	optionsMap,
		db:				db,
		packetCache:	packetCache,
		workerPool:		make(chan struct{}, numWorkers),
		packetch:		make(chan packetJob, 1000), // Can hold 1000 packets
		ipch:			make(chan net.IP),
		sendch:			make(chan []byte, 1000), // Can hold 1000 queued packets to be sent
		quitch:			make(chan struct{}),
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
	go s.packetCache.CleanJob(time.Duration(time.Second * 5))

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

func GetServer() *Server {
	s := globServer.Load()
	return s.(*Server)	

}

func SetServer(s *Server) {
	globServer.Store(s)
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
		return fmt.Errorf("Failed to send packet: %w", err)
	}
	return nil
}

func (s *Server) worker() {
    for job := range s.packetch {
        s.workerPool <- struct{}{} 
        err := s.handleDHCPPacket(job.data, job.clientAddr, s.config); if err != nil {
			slog.Error(fmt.Sprintf("Error occured while handline dhcp packet: %v", err))
		}
		// Reads one item off the worker queue 
        <-s.workerPool 
	}
}

// Function to handle a DHCP packet in a new goroutine
func (s *Server) handleDHCPPacket(packetSlice []byte, clientAddr *net.UDPAddr, config c.Config) error {
	dhcpLayer, ok := gopacket.NewPacket(packetSlice, layers.LayerTypeDHCPv4, gopacket.Default).Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4)
	if !ok {
		return fmt.Errorf("Error getting dhcp layer from packet")
	}

	switch message, _ := dhcpUtils.GetMessageTypeOption(dhcpLayer.Options); message {
	case layers.DHCPMsgTypeDiscover:
		slog.Debug("Got Discover")
		err := s.createOffer(dhcpLayer); if err != nil {
			return fmt.Errorf("Error creating offer: %v", err)
		}
	case layers.DHCPMsgTypeRequest:
		slog.Debug("Got Request")
		err := s.processRequest(dhcpLayer); if err != nil {
			return fmt.Errorf("Error processing request: %v", err)
		}
	case layers.DHCPMsgTypeOffer:
		slog.Debug("Got Offer")
	case layers.DHCPMsgTypeDecline:
		slog.Debug("Got Decline")
		err := s.processDecline(dhcpLayer); if err != nil {
			return fmt.Errorf("Error processing decline: %v", err)
		}
	case layers.DHCPMsgTypeAck:
		log.Printf("Got Ack")
	case layers.DHCPMsgTypeNak:
		log.Printf("Got Nak")
	case layers.DHCPMsgTypeRelease:
		log.Printf("Got Release")
	case layers.DHCPMsgTypeInform:
		log.Printf("Got Inform")
	case layers.DHCPMsgTypeUnspecified:
		log.Printf("Error, DHCP operation type is unspecified")
	}

	return nil
}

func (s *Server) GenerateIP(db *sql.DB,  config *c.Config) (net.IP, error) {
	ips, err := database.GetLeasedIPs(db); if err != nil {
		return nil, fmt.Errorf("Error getting leases from database: %v\n", err)
	}

	startIP := net.ParseIP(config.DHCP.AddrPool[0])
	endIP := net.ParseIP(config.DHCP.AddrPool[1])

	for ip := startIP; !database.IsIPEqual(ip, endIP); ip = database.IncrementIP(ip) {
		if !database.IPsContains(ips, ip) {
			if !s.IsOccupiedStatic(ip) {
				return ip, nil
			}
		}
	}
	
	return nil, fmt.Errorf("Unable to generate IP addr, pool full?")
}	