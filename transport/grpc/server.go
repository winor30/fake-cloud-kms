package grpcserver

import (
	"context"
	"log/slog"
	"net"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc"

	"github.com/winor30/fake-cloud-kms/service"
	"github.com/winor30/fake-cloud-kms/transport/grpc/interceptor"
)

// Server wraps the gRPC server lifecycle for the KMS emulator.
type Server struct {
	grpcServer *grpc.Server
}

// New creates a gRPC server that exposes the provided KMS service.
func New(svc service.KMSService, opts ...grpc.ServerOption) *Server {
	opts = append(opts, grpc.ChainUnaryInterceptor(interceptor.ErrorInterceptor()))
	grpcServer := grpc.NewServer(opts...)
	kmspb.RegisterKeyManagementServiceServer(grpcServer, newHandler(svc))
	return &Server{grpcServer: grpcServer}
}

// ListenAndServe listens on addr and serves requests until the context is canceled.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, lis)
}

// Serve starts handling requests on the provided listener until the context is canceled.
func (s *Server) Serve(ctx context.Context, lis net.Listener) error {
	slog.InfoContext(ctx, "Cloud KMS emulator listening", "addr", lis.Addr().String())
	go func() {
		<-ctx.Done()
		s.grpcServer.GracefulStop()
	}()
	return s.grpcServer.Serve(lis)
}
