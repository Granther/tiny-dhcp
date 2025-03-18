package logger

import (
	"fmt"
	"io"
	"os"
	"log/slog"
	"slices"
)

func CreateLogger(logLevel, logsPath string, std bool) error {
	levels := map[string]slog.Level{
		"debug": slog.LevelDebug,
		"info":  slog.LevelInfo,
	}

	if !slices.Contains([]string{"debug", "info"}, logLevel) { // Is `logLevel` "debug" || "info"
		return fmt.Errorf("%s is not supported log level", logLevel)
	}

	handlerOpts := &slog.HandlerOptions{
		Level: levels[logLevel],
	}

	var logger *slog.Logger
	if !std { // Log to os.Stderr
		f, err := openLogsFile(fmt.Sprintf("%s/%s.log", logsPath, logLevel))
		if err != nil { return fmt.Errorf("opening logs file: %w", err) } 
		logger = slog.New(slog.NewTextHandler(f, handlerOpts))
	} else { // Log to file
		logger = slog.New(slog.NewTextHandler(os.Stderr, handlerOpts))
	}
	slog.SetDefault(logger) // Set global slog logger

	return nil
}

func openLogsFile(path string) (io.Writer, error) {
	return os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
}

