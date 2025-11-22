package cmdutil

import (
	"context"
	"fmt"
	"log/slog"
	"os"
)

// ExitStatus represents a Posix exit status that a command expects to be returned to the shell.
type ExitStatus int

const (
	// ExitSuccess returns the success status.
	ExitSuccess ExitStatus = iota
	// ExitFailure returns the failure status.
	ExitFailure
)

// Errorf returns the exit status with log output.
func Errorf(ctx context.Context, msg string, err error) ExitStatus {
	slog.ErrorContext(ctx, msg, slog.Any("error", err))
	fmt.Fprintf(os.Stderr, "%s: %v\n", msg, err)
	return ExitFailure
}
