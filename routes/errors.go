package routes

import (
	"net/http"

	"git.containerum.net/ch/grpc-proto-files/utils"
	"git.containerum.net/ch/json-types/errors"
	"google.golang.org/grpc/status"
)

func handleServerError(err error) (statusCode int, msg *errors.Error) {
	if grpcErr, ok := status.FromError(err); ok {
		if code, hasCode := grpcutils.GRPCToHTTPCode[grpcErr.Code()]; hasCode {
			statusCode = code
			msg = errors.New(grpcErr.Message())
			return
		}
	}
	statusCode = http.StatusInternalServerError
	msg = errors.New(err.Error())
	return
}
