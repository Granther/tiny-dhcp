package config

// Configurations exported
type Configurations struct {
	Metal		MetalConfigurations
	Server		ServerConfigurations
}

type MetalConfigurations struct {
	Port		int
	Interface	string
}

type ServerConfigurations struct {
	Subnet		string
	Gateway		string
	DNS			string
	LeaseLen	int
	IPRange		string
}
