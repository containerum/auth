package validation

import (
	"context"

	"git.containerum.net/ch/grpc-proto-files/auth"
	"git.containerum.net/ch/kube-client/pkg/cherry"
	"git.containerum.net/ch/kube-client/pkg/cherry/adaptors/cherrylog"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"
	"gopkg.in/go-playground/validator.v8"
)

// ValidationProxy is a special wrapper to validate incoming requests and then call "upstream"
type ValidationProxy struct {
	upstream      auth.AuthServer
	log           *cherrylog.LogrusAdapter
	validator     *validator.Validate
	validationErr func() *cherry.Err
}

// NewValidationProxy constructs ValidationProxy
func NewValidationProxy(upstream auth.AuthServer, validator *validator.Validate, validationErr func() *cherry.Err) auth.AuthServer {
	return &ValidationProxy{
		upstream:      upstream,
		log:           cherrylog.NewLogrusAdapter(logrus.WithField("component", "validation_proxy")),
		validator:     validator,
		validationErr: validationErr,
	}
}

func (v *ValidationProxy) validateStruct(req interface{}) error {
	v.log.Debugf("validating struct %T", req)
	err := v.validator.Struct(req)
	if err != nil {
		if validatorErrs, ok := err.(validator.ValidationErrors); ok {
			ret := v.validationErr()
			// TODO: maybe return "json" field name
			for fieldName, fieldErr := range validatorErrs {
				if fieldErr == nil {
					continue
				}
				ret.AddDetailF("field %s: validation failed for %s tag", fieldName, fieldErr.Tag)
			}
			err = ret
		} else {
			err = v.validationErr().AddDetailsErr(err).Log(err, v.log)
		}
	}
	return err
}

func (v *ValidationProxy) CreateToken(ctx context.Context, req *auth.CreateTokenRequest) (*auth.CreateTokenResponse, error) {
	if err := v.validateStruct(req); err != nil {
		return nil, err
	}
	return v.upstream.CreateToken(ctx, req)
}

func (v *ValidationProxy) CheckToken(ctx context.Context, req *auth.CheckTokenRequest) (*auth.CheckTokenResponse, error) {
	if err := v.validateStruct(req); err != nil {
		return nil, err
	}
	return v.upstream.CheckToken(ctx, req)
}

func (v *ValidationProxy) ExtendToken(ctx context.Context, req *auth.ExtendTokenRequest) (*auth.ExtendTokenResponse, error) {
	if err := v.validateStruct(req); err != nil {
		return nil, err
	}
	return v.upstream.ExtendToken(ctx, req)
}

func (v *ValidationProxy) UpdateAccess(ctx context.Context, req *auth.UpdateAccessRequest) (*empty.Empty, error) {
	if err := v.validateStruct(req); err != nil {
		return nil, err
	}
	return v.upstream.UpdateAccess(ctx, req)
}

func (v *ValidationProxy) GetUserTokens(ctx context.Context, req *auth.GetUserTokensRequest) (*auth.GetUserTokensResponse, error) {
	if err := v.validateStruct(req); err != nil {
		return nil, err
	}
	return v.upstream.GetUserTokens(ctx, req)
}

func (v *ValidationProxy) DeleteToken(ctx context.Context, req *auth.DeleteTokenRequest) (*empty.Empty, error) {
	if err := v.validateStruct(req); err != nil {
		return nil, err
	}
	return v.upstream.DeleteToken(ctx, req)
}

func (v *ValidationProxy) DeleteUserTokens(ctx context.Context, req *auth.DeleteUserTokensRequest) (*empty.Empty, error) {
	if err := v.validateStruct(req); err != nil {
		return nil, err
	}
	return v.upstream.DeleteUserTokens(ctx, req)
}
