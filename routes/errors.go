package routes

import (
	"git.containerum.net/ch/kube-client/pkg/cherry"
	"git.containerum.net/ch/kube-client/pkg/cherry/auth"
)

func handleServerError(err error) (statusCode int, ret *cherry.Err) {
	switch err.(type) {
	case *cherry.Err:
		ret = err.(*cherry.Err)
		statusCode = ret.StatusHTTP
		return
	default:
		ret = autherr.ErrInternal()
		statusCode = ret.StatusHTTP
		return
	}
}
