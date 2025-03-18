package main

import (
	"log/slog"
	"os"

	"gdhcp/internal/config"
	"gdhcp/internal/utils/logger"
	"gdhcp/internal/server"
	"gdhcp/internal/pkg/errors"
)

func main() {
	jsonConfig := config.NewJSONConfigManager(".")
	config, err := jsonConfig.ReadConfig()
	errors.CheckErrorMsg("Error parsing config file", err)

	err = CreateLogger(config.Server.LogLevel)
	errors.CheckErrorMsg("Error creating logger", err)

	server, err := server.NewServer(&config)
	errors.CheckErrorMsg("Error occured while instantiating server", err)
	
	server.Start()
}
