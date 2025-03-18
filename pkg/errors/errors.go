package errors

import (
	"os"
	"log/slog"
)

// If `err` != nil, exit with error message `msg`
CheckErrorMsg(msg string, err error) {
	if err != nil {
		slog.Error(msg, "error", err)
		os.Exit(1)
	}
}
