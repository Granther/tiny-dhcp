package logger

import (
	"fmt"
	"log/slog"
	"slices"
)

func CreateLogger(logLevel, logPath string, std bool) error {
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
	if std { // Log to os.Stderr
		logger := slog.New(slog.NewTextHandler(os.Stderr, handlerOpts))
	} else { // Log to file
		logger := slog.New(slog.NewTextHandler(os.Stderr, handlerOpts))
	}
	slog.SetDefault(logger) // Set global slog logger

	return nil
}

