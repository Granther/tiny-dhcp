package utils

import "github.com/google/gopacket/layers"

// Attempts to extact specific DHCP option from DHCP options
func GetDHCPOption(options *layers.DHCPOptions, optType layers.DHCPOpt) (layers.DHCPOption, bool) {
	for _, option := range *options {
		if option.Type == optType {
			return option, true
		}
	}
	return layers.DHCPOption{}, false
}

// Returns the DHCP message type from options
func GetMessageTypeOption(options *layers.DHCPOptions) (layers.DHCPMsgType, bool) {
	opt, found := GetDHCPOption(options, layers.DHCPOptMessageType)

	// If the MessageType option is valid, try to convert
	if found && len(opt.Data) > 0 {
		return layers.DHCPMsgType(opt.Data[0]), true
	}
	return layers.DHCPMsgTypeUnspecified, false
}
