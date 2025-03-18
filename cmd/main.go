package main

import (
	"gdhcp/internal/config"
	"gdhcp/internal/utils/logger"
	"gdhcp/internal/server"
	"gdhcp/pkg/errors"
)

func main() {
	jsonConfig := config.NewJSONConfigManager("configs")
	config, err := jsonConfig.ReadConfig()
	errors.ExitErrorMsg("parsing config file", err)

	err = logger.CreateLogger(config.Server.LogLevel, config.Server.LogsPath, config.Server.StderrLogs)
	errors.ExitErrorMsg("creating logger", err)

	server, err := server.NewServer(&config)
	errors.ExitErrorMsg("instantiating server", err)
	
	server.Start()
}
