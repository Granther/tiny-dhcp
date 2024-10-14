package database

import (
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Define the network interface to use (e.g., eth0)
	ifaceName := "wlp2s0"
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Could not find interface %s: %v", ifaceName, err)
	}

	// Target IP address to ARP
	targetIP := net.ParseIP("192.168.1.2")

	// Get your local IP on this interface (e.g., 192.168.1.X)
	localIP, err := getLocalIP(iface)
	if err != nil {
		log.Fatalf("Could not get local IP: %v", err)
	}

	// Open a raw socket for this interface
	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening pcap handle: %v", err)
	}
	defer handle.Close()

	// Create an ARP request
	arpRequest := createARPRequest(iface.HardwareAddr, localIP, targetIP)

	// Send ARP request
	if err := handle.WritePacketData(arpRequest); err != nil {
		log.Fatalf("Error sending ARP request: %v", err)
	}

	// Wait for the ARP response
	fmt.Println("Waitinh")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer != nil {
			arp, ok := arpLayer.(*layers.ARP); if !ok {
				fmt.Println("Did not do arp layer")
			}
			fmt.Printf("Op: %v\n", arp.Operation)
			if arp.Operation == layers.ARPReply && net.IP(arp.SourceProtAddress).Equal(targetIP) {
				fmt.Printf("Received ARP reply from %v: MAC %v\n", targetIP, net.HardwareAddr(arp.SourceHwAddress))
				break
			}
		}
	}
}

// getLocalIP gets the local IP address on the provided network interface.
func getLocalIP(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
			return ipNet.IP, nil
		}
	}
	return nil, fmt.Errorf("No IPv4 address found on interface %s", iface.Name)
}

// createARPRequest crafts an ARP request packet
func createARPRequest(srcMAC net.HardwareAddr, srcIP, dstIP net.IP) []byte {
	ethLayer := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // Broadcast MAC
		EthernetType: layers.EthernetTypeARP,
	}

	arpLayer := &layers.ARP{
		AddrType:		   layers.LinkTypeEthernet,
		Protocol:		   layers.EthernetTypeIPv4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Unknown target MAC
		DstProtAddress:    dstIP.To4(),
		HwAddressSize:     6,
		ProtAddressSize:   4,
	}

	// type ARP struct {
	// 	BaseLayer
	// 	AddrType          LinkType
	// 	Protocol          EthernetType
	// 	HwAddressSize     uint8
	// 	ProtAddressSize   uint8//   
	// 	Operation         uint16
	// 	SourceHwAddress   []byte
	// 	SourceProtAddress []byte
	// 	DstHwAddress      []byte
	// 	DstProtAddress    []byte
	// }

	// Serialize the layers into a byte buffer
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buffer, opts, ethLayer, arpLayer)

	return buffer.Bytes()
}

// func IsOccupiedStatic(ip net.IP) bool {

// }

// Client needs addr generated
// 