package config

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/viper"
)

type ConfigHandler interface {
	ReadConfig() (Config, error)
	WriteConfig(config *Config) error
	GetDefaultConfig() *Config
}

type JSONConfigManager struct {
	configPath string
}

type DHCP struct {
	NetworkAddr     string   `json:"networkAddr"`
	AddrPool        []string `json:"addrPool"`
	SubnetMask      string   `json:"subnetMask"`
	Router          string   `json:"router"`
	TimeServer      []string `json:"timeServer"`
	NameServer      []string `json:"nameServer"`
	DNSServer       []string `json:"dnsServer"`
	LogServer       []string `json:"logServer"`
	LeaseLen        int      `json:"leaseLen"`
	DomainName      string   `json:"domainName"`
	IPForwarding    bool     `json:"ipForwarding"`
	DatagramMTU     int      `json:"datagramMTU"`
	DefaultTTL      int      `json:"defaultTTL"`
	TCPTTL          int      `json:"tcpTTL"`
	BroadcastAddr   string   `json:"broadcastAddr"`
	RouterDiscovery bool     `json:"routerDiscovery"`
	NTPServer       []string `json:"ntpServer"`
}

type Server struct {
	Port            int    `json:"port"`
	ListenInterface string `json:"listenInterface"`
	NumWorkers      int    `json:"numWorkers"`
	LogLevel        string `json:"logLevel"`
}

type Config struct {
	Server Server `json:"server"`
	DHCP   DHCP   `json:"dhcp"`
}

func NewJSONConfigManager(configPath string) ConfigHandler {
	return &JSONConfigManager{
		configPath: configPath,
	}
}

func (j *JSONConfigManager) ReadConfig() (Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("json")
	viper.AddConfigPath(j.configPath)

	if err := viper.ReadInConfig(); err != nil {
		return Config{}, fmt.Errorf("error reading config file: %w", err)
	}

	var config Config
	err := viper.Unmarshal(&config)
	if err != nil {
		return Config{}, fmt.Errorf("error occured while unmarshaling config: %w", err)
	}

	return config, nil
}

func (j *JSONConfigManager) WriteConfig(config *Config) error {
	jsonData, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		return fmt.Errorf("error marshaling config to JSON: %w", err)
	}

	writePath := j.configPath + "config.json"
	err = os.WriteFile(writePath, jsonData, 0666)
	if err != nil {
		return fmt.Errorf("error writing marshalled JSON to config file: %w", err)
	}

	return nil
}

func (j *JSONConfigManager) GetDefaultConfig() *Config {
	return &Config{
		Server: Server{
			Port:            100,
			ListenInterface: "any",
			NumWorkers:      10,
			LogLevel:        "debug",
		},
		DHCP: DHCP{
			NetworkAddr:     "192.168.1.0/24",
			AddrPool:        []string{"192.168.1.20", "192.168.1.240"},
			SubnetMask:      "255.255.255.0",
			Router:          "192.168.1.1",
			TimeServer:      []string{},
			NameServer:      []string{},
			DNSServer:       []string{},
			LogServer:       []string{},
			LeaseLen:        30000,
			DomainName:      "local",
			IPForwarding:    true,
			DatagramMTU:     1500,
			DefaultTTL:      254,
			TCPTTL:          254,
			BroadcastAddr:   "255.255.255.255",
			RouterDiscovery: true,
			NTPServer:       []string{},
		},
	}
}
