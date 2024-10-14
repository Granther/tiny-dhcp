package main

import (
	"fmt"
	"log"
	"log/slog"

	c "gdhcp/config"
	server "gdhcp/server"
)

func CreateLogger(logLevel string) {
	levels := map[string]slog.Level{
		"debug": slog.LevelDebug,
		"info": slog.LevelInfo,
	}
	
	handlerOpts := &slog.HandlerOptions{
		Level: levels[logLevel],
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, handlerOpts))
	slog.SetDefault(logger)
}

func main() {
	config, err := c.ReadConfig("."); if err != nil {
		log.Fatalf("Error parsing config file: %v", err)
		os.Exit(1)
		return
	}

	CreateLogger(config.Server.LogLevel)
	c.SetConfig(&config)

	server, err := server.NewServer(config)
	if err != nil {
		slog.Error(fmt.Sprintf("Error occured while instantiating server: %v", err))
		return
	}
	server.Start()
}