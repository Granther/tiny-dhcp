package utils

import "github.com/google/gopacket/layers"

func GetDHCPOption(options layers.DHCPOptions, optType layers.DHCPOpt) (layers.DHCPOption, bool) {
	var opt layers.DHCPOption

	for _, option := range options {
		if option.Type == optType {
			return option, true
		}
	}
	return opt, false
}

func GetMessageTypeOption(options layers.DHCPOptions) (layers.DHCPMsgType, bool) {
	opt, found := GetDHCPOption(options, layers.DHCPOptMessageType)

	// If the MessageType option is valid, try to convert
	if found && len(opt.Data) > 0 {
		return layers.DHCPMsgType(opt.Data[0]), true
	}
	return layers.DHCPMsgTypeUnspecified, false
}
