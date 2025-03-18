package server

import (
	"fmt"
	"gdhcp/config"
	"log/slog"
	"os"
	"testing"
)

func TestGenerateIP(t *testing.T) {
	jsonConfig := config.NewJSONConfigManager(".")
	config, err := jsonConfig.ReadConfig()
	if err != nil {
		slog.Error("Error parsing config file", "error", err)
		os.Exit(1)
	}

	server, err := NewServer(&config)
	if err != nil {
		slog.Error("Error occured while instantiating server", "error", err)
		os.Exit(1)
	}

	ip, err := server.GenerateIP()
	fmt.Println(ip.String())
	// if err != nil {
	// 	t.Errorf("VisitTryStmt failed: %v", err)
	// }
}
