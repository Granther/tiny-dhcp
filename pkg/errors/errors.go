package errors

import (
	"os"
	"fmt"
)

// If `err` != nil, exit with error message `msg`
func ExitErrorMsg(msg string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR %s: %s\n", msg, err)
		os.Exit(1)
	}
}
