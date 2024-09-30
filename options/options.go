package main

import (
	// "log"
	"fmt"
	"net"

	"github.com/google/gopacket/layers"

	c "gdhcp/config"
)

type OptionHandler func(dhcpRequest *layers.DHCPv4, config c.Config)

func handleBroadcastAddr(dhcpRequest *layers.DHCPv4, config c.Config) {
	return net.ParseIP(config.DHCP.BroadcastAddr).To4()
}

//func FufillRequestList

func main() {
	var optionHandlers = map[layers.DHCPOpt]OptionHandler{
		layers.DHCPOptBroadcastAddr: handleBroadcast,
	}

	handler, _ := optionHandlers[layers.DHCPOptBroadcastAddr]
	handler("hello")
}

