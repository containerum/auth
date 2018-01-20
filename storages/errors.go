package storages

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	errInvalidToken          = status.Error(codes.InvalidArgument, "invalid token received")
	errTokenNotOwnedBySender = status.Error(codes.PermissionDenied, "can`t identify sender as token owner")
	errStorage               = status.Error(codes.Internal, "storage internal error")
	errTokenFactory          = status.Error(codes.Internal, "token factory failed")
)
