package interceptor

import (
	"context"
	"errors"
	"log/slog"

	serviceerrors "github.com/winor30/fake-cloud-kms/errors/service"
	storeerrors "github.com/winor30/fake-cloud-kms/errors/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var errToStatus = map[error]codes.Code{
	serviceerrors.ErrInvalidArgument:    codes.InvalidArgument,
	serviceerrors.ErrNotFound:           codes.NotFound,
	serviceerrors.ErrAlreadyExists:      codes.AlreadyExists,
	serviceerrors.ErrFailedPrecondition: codes.FailedPrecondition,
	serviceerrors.ErrUnimplemented:      codes.Unimplemented,
	storeerrors.ErrNotFound:             codes.NotFound,
	storeerrors.ErrAlreadyExists:        codes.AlreadyExists,
	serviceerrors.ErrInternal:           codes.Internal,
}

func ErrorInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		res, err := handler(ctx, req)
		if err != nil {
			slog.ErrorContext(ctx, "error handling request", "error", err)
			return nil, toStatus(err)
		}
		return res, nil
	}
}

func toStatus(err error) error {
	for target, statusCode := range errToStatus {
		if errors.Is(err, target) {
			return status.Error(statusCode, err.Error())
		}
	}
	return status.Error(codes.Internal, err.Error())
}
