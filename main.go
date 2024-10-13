package main

import (
	"os"
	"io"
	"net"
	"fmt"
	"log"
	"log/slog"
	"database/sql"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"

	c "gdhcp/config"
	dhcpUtils "gdhcp/dhcp"
	deviceUtils "gdhcp/device"
	options "gdhcp/options"
	database "gdhcp/database"
)

type Server struct {
	conn		*net.UDPConn
	handle		*pcap.Handle
	serverIP	net.IP
	serverMAC	net.HardwareAddr
	config		c.Config
	optionsMap	map[layers.DHCPOpt]options.DHCPOptionValue
	db			*sql.DB
	workerPool	chan struct{}
	packetch 	chan packetJob
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

	return &Server{
		conn:		conn,
		handle:		handle,
		serverIP:	serverIP.IP,
		serverMAC:	iface.HardwareAddr,
		config:		config,
		optionsMap: optionsMap,
		db:			db,
		workerPool:	make(chan struct{}, numWorkers),
		packetch:	make(chan packetJob, 1000), // Can hold 1000 packets
		sendch:		make(chan []byte, 1000), // Can hold 1000 queued packets to be sent
		quitch:		make(chan struct{}),
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

	slog.Info("Server is now listening for packets/quitch")
	// Wait for quit signal
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
        <-s.workerPool 
	}
}

func CreateLogger(logLevel string, logsDir string) {
	levels := map[string]slog.Level{
		"debug": slog.LevelDebug,
		"info": slog.LevelInfo,
	}
	
	handlerOpts := &slog.HandlerOptions{
		Level: levels[logLevel],
	}

	file, err := os.OpenFile(fmt.Sprintf("%v/logs.log", logsDir), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0777)
    if err != nil {
        log.Fatalf("Failed to open log file: %v", err)
    }

    multiWriter := io.MultiWriter(os.Stderr, file)
	logger := slog.New(slog.NewTextHandler(multiWriter, handlerOpts))
	slog.SetDefault(logger)
}

func main() {
	config, err := c.ReadConfig("."); if err != nil {
		log.Fatalf("Error parsing config file: %v", err)
		os.Exit(1)
		return
	}

	CreateLogger(config.Server.LogLevel, config.Server.LogsDir)

	server, err := NewServer(config)
	if err != nil {
		slog.Error(fmt.Sprintf("Error occured while instantiating server: %v", err))
		return
	}
	server.Start()
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
			return fmt.Errorf("Error creating offer: %w\n", err)
		}
	case layers.DHCPMsgTypeRequest:
		slog.Debug("Got Request")
		err := s.processRequest(dhcpLayer); if err != nil {
			return fmt.Errorf("Error processing request: %w\n", err)
		}
	case layers.DHCPMsgTypeOffer:
		log.Printf("Got Offer")
	case layers.DHCPMsgTypeDecline:
		log.Printf("Got Decline")
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

// If nil, essentially drop the packet
// if dhcp_packet == nil || dhcp_layer == nil{
// 	log.Printf("Error, unable to get DHCP packet or layer")
// 	return
// }
// dhcp, _ := dhcp_layer.(*layers.DHCPv4)