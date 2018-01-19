package routes

import (
	"encoding/json"
	"net/http"

	"git.containerum.net/ch/grpc-proto-files/utils"
	"git.containerum.net/ch/json-types/errors"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/status"
)

func sendErrorsWithCode(w http.ResponseWriter, errs []string, code int) {
	body, err := json.Marshal(errors.Format("%v", errs))
	logrus.WithField("errors", errs).WithField("code", code).Debugf("Sending errors")
	if err != nil {
		logrus.Errorf("JSON Marshal: %v", err)
	}
	_, err = w.Write(body)
	if err != nil {
		logrus.Errorf("Response write: %v", err)
	}
	w.WriteHeader(code)
}

func sendError(w http.ResponseWriter, err error) {
	var body []byte
	var code int
	if grpcStatus, ok := status.FromError(err); ok {
		body, _ = json.Marshal(errors.New(grpcStatus.Message()))
		code = grpcutils.GRPCToHTTPCode[grpcStatus.Code()]
	} else {
		body, _ = json.Marshal(errors.New(err.Error()))
		code = http.StatusInternalServerError
	}

	logrus.WithError(err).WithField("code", code).Debugf("Sending error")
	_, err = w.Write(body)
	if err != nil {
		logrus.Errorf("Response write: %v", err)
	}
	w.WriteHeader(code)
}
