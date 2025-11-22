package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/winor30/fake-cloud-kms/cmdutil"
	"github.com/winor30/fake-cloud-kms/kmscrypto"
	"github.com/winor30/fake-cloud-kms/seed"
	"github.com/winor30/fake-cloud-kms/service"
	"github.com/winor30/fake-cloud-kms/store"
	"github.com/winor30/fake-cloud-kms/store/memory"
	grpcserver "github.com/winor30/fake-cloud-kms/transport/grpc"
)

// Config captures runtime flags for the emulator binary.
type Config struct {
	ListenAddr string
	SeedFile   string
	Store      store.StoreType
	LogLevel   slog.Level
}

func main() {
	os.Exit(int(run()))
}

func run() cmdutil.ExitStatus {
	cfg, err := parseConfig(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return cmdutil.ExitSuccess
		}
		return cmdutil.Errorf(context.Background(), "parse flags", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	strg, err := newStore(cfg.Store)
	if err != nil {
		return cmdutil.Errorf(ctx, "invalid store", err)
	}

	engine := kmscrypto.NewTinkEngine()
	kmsService := service.New(strg, engine)

	if cfg.SeedFile != "" {
		if err := seed.Apply(ctx, kmsService, cfg.SeedFile); err != nil {
			return cmdutil.Errorf(ctx, "failed to apply seed file", err)
		}
	}

	srv := grpcserver.New(kmsService)
	if err := srv.ListenAndServe(ctx, cfg.ListenAddr); err != nil && !errors.Is(err, context.Canceled) {
		return cmdutil.Errorf(ctx, "server error", err)
	}
	return cmdutil.ExitSuccess
}

func parseConfig(args []string) (*Config, error) {
	cfg := &Config{
		ListenAddr: "127.0.0.1:9010", // loopback default prevents accidental public exposure
		Store:      store.StoreTypeMemory,
		LogLevel:   slog.LevelInfo,
	}

	fs := flag.NewFlagSet("fake-cloud-kms", flag.ContinueOnError)
	fs.StringVar(&cfg.ListenAddr, "grpc-listen-addr", cfg.ListenAddr, "gRPC listen address (host:port)")
	fs.StringVar(&cfg.SeedFile, "seed-file", "", "Optional path to yaml seed definition")
	// custom parser for store
	fs.Func("store", "State store (memory)", func(s string) error {
		t := store.StoreType(strings.ToLower(strings.TrimSpace(s)))
		switch t {
		case store.StoreTypeMemory, "":
			cfg.Store = store.StoreTypeMemory
			return nil
		default:
			return fmt.Errorf("unsupported store %q", s)
		}
	})
	// custom parser for log level
	fs.Func("log-level", "Log level (debug, info, warn, error)", func(s string) error {
		level, err := parseLogLevel(s)
		if err != nil {
			return err
		}
		cfg.LogLevel = level
		return nil
	})

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	return cfg, nil
}

func parseLogLevel(raw string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unsupported log level %q", raw)
	}
}

func newStore(storeType store.StoreType) (store.Store, error) {
	switch storeType {
	case store.StoreTypeMemory:
		return memory.New(), nil
	default:
		return nil, fmt.Errorf("unsupported store %q", string(storeType))
	}
}
