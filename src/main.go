package main

import (
	"gdhcp/config"
	"gdhcp/server"
	"log/slog"
	"os"
)

func CreateLogger(logLevel string) {
	levels := map[string]slog.Level{
		"debug": slog.LevelDebug,
		"info":  slog.LevelInfo,
	}

	handlerOpts := &slog.HandlerOptions{
		Level: levels[logLevel],
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, handlerOpts))
	slog.SetDefault(logger)
}

func main() {
	jsonConfig := config.NewJSONConfigManager(".")
	config, err := jsonConfig.ReadConfig()
	if err != nil {
		slog.Error("Error parsing config file", "error", err)
		os.Exit(1)
	}

	CreateLogger(config.Server.LogLevel)

	server, err := server.NewServer(&config)
	if err != nil {
		slog.Error("Error occured while instantiating server", "error", err)
		os.Exit(1)
	}
	server.Start()
}
