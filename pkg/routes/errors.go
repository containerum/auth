package routes

import (
	"git.containerum.net/ch/auth/pkg/errors"
	"github.com/containerum/cherry"
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

func badRequest(err error) (statusCode int, ret *cherry.Err) {
	ret = autherr.ErrValidation().AddDetailsErr(err)
	return ret.StatusHTTP, ret
}
