package emulator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"

	"google.golang.org/grpc"

	"github.com/winor30/fake-cloud-kms/kmscrypto"
	"github.com/winor30/fake-cloud-kms/seed"
	"github.com/winor30/fake-cloud-kms/service"
	"github.com/winor30/fake-cloud-kms/store"
	"github.com/winor30/fake-cloud-kms/store/memory"
	grpcserver "github.com/winor30/fake-cloud-kms/transport/grpc"
)

// Options controls in-process emulator startup.
type Options struct {
	// ListenAddr defaults to 127.0.0.1:0 (ephemeral port).
	ListenAddr string
	// Store allows injecting a custom storage backend. Defaults to in-memory.
	Store store.Store
	// SeedFile optionally applies the seed file before serving.
	SeedFile string
	// Logger overrides the default slog logger.
	Logger *slog.Logger
	// GRPCServerOptions allows passing extra grpc.ServerOption values.
	GRPCServerOptions []grpc.ServerOption
}

// Instance represents a running emulator.
type Instance struct {
	// Addr is the listen address (host:port).
	Addr string
	stop func(context.Context) error
}

// Stop gracefully shuts down the emulator, waiting for in-flight RPCs to finish.
func (i *Instance) Stop(ctx context.Context) error {
	if i == nil || i.stop == nil {
		return nil
	}
	return i.stop(ctx)
}

// Start launches the emulator in-process and returns an Instance handle.
func Start(ctx context.Context, opts Options) (*Instance, error) {
	if opts.ListenAddr == "" {
		opts.ListenAddr = "127.0.0.1:0"
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	strg := opts.Store
	if strg == nil {
		strg = memory.New()
	}

	engine := kmscrypto.NewTinkEngine()
	svc := service.New(strg, engine)

	if opts.SeedFile != "" {
		if err := seed.Apply(ctx, svc, opts.SeedFile); err != nil {
			return nil, fmt.Errorf("apply seed file: %w", err)
		}
	}

	lis, err := net.Listen("tcp", opts.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	srv := grpcserver.New(svc, opts.GRPCServerOptions...)
	runCtx, cancel := context.WithCancel(ctx)
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(runCtx, lis)
	}()

	stop := func(stopCtx context.Context) error {
		cancel()
		select {
		case err := <-errCh:
			if err == nil || errors.Is(err, grpc.ErrServerStopped) || errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		case <-stopCtx.Done():
			return stopCtx.Err()
		}
	}

	logger.InfoContext(ctx, "fake-cloud-kms emulator started", "addr", lis.Addr().String())

	return &Instance{
		Addr: lis.Addr().String(),
		stop: stop,
	}, nil
}
