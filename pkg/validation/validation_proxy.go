package validation

import (
	"context"

	"git.containerum.net/ch/auth/proto"
	"git.containerum.net/ch/kube-client/pkg/cherry"
	"git.containerum.net/ch/kube-client/pkg/cherry/adaptors/cherrylog"
	chutils "git.containerum.net/ch/utils"
	"github.com/go-playground/universal-translator"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"
	"gopkg.in/go-playground/validator.v9"
)

// ServerWrapper is a special wrapper to Validate incoming requests and then call "upstream"
type ServerWrapper struct {
	upstream      authProto.AuthServer
	log           *cherrylog.LogrusAdapter
	validator     *validator.Validate
	validationErr func() *cherry.Err
	translator    *ut.UniversalTranslator
}

// NewServerWrapper constructs ServerWrapper
func NewServerWrapper(upstream authProto.AuthServer, validator *validator.Validate,
	translator *ut.UniversalTranslator, validationErr func() *cherry.Err) authProto.AuthServer {
	return &ServerWrapper{
		upstream:      upstream,
		log:           cherrylog.NewLogrusAdapter(logrus.WithField("component", "validation_proxy")),
		validator:     validator,
		validationErr: validationErr,
		translator:    translator,
	}
}

func (v *ServerWrapper) validateStruct(ctx context.Context, req interface{}) error {
	v.log.Debugf("validating struct %T", req)
	err := v.validator.StructCtx(ctx, req)
	if err != nil {
		if validatorErrs, ok := err.(validator.ValidationErrors); ok {
			ret := v.validationErr()
			for _, fieldErr := range validatorErrs {
				if fieldErr == nil {
					continue
				}
				acceptedLangs := chutils.GetAcceptedLanguages(ctx)
				translator, _ := v.translator.FindTranslator(acceptedLangs...)
				ret.AddDetailF("Field %s: %s", fieldErr.Namespace(), fieldErr.Translate(translator))
			}
			err = ret
		} else {
			err = v.validationErr().AddDetailsErr(err).Log(err, v.log)
		}
	}
	return err
}

// CreateToken performs request validation and calls underlying method
func (v *ServerWrapper) CreateToken(ctx context.Context, req *authProto.CreateTokenRequest) (*authProto.CreateTokenResponse, error) {
	if err := v.validateStruct(ctx, req); err != nil {
		return nil, err
	}
	return v.upstream.CreateToken(ctx, req)
}

// CheckToken performs request validation and calls underlying method
func (v *ServerWrapper) CheckToken(ctx context.Context, req *authProto.CheckTokenRequest) (*authProto.CheckTokenResponse, error) {
	if err := v.validateStruct(ctx, req); err != nil {
		return nil, err
	}
	return v.upstream.CheckToken(ctx, req)
}

// ExtendToken performs request validation and calls underlying method
func (v *ServerWrapper) ExtendToken(ctx context.Context, req *authProto.ExtendTokenRequest) (*authProto.ExtendTokenResponse, error) {
	if err := v.validateStruct(ctx, req); err != nil {
		return nil, err
	}
	return v.upstream.ExtendToken(ctx, req)
}

// UpdateAccess performs request validation and calls underlying method
func (v *ServerWrapper) UpdateAccess(ctx context.Context, req *authProto.UpdateAccessRequest) (*empty.Empty, error) {
	if err := v.validateStruct(ctx, req); err != nil {
		return nil, err
	}
	return v.upstream.UpdateAccess(ctx, req)
}

// GetUserTokens performs request validation and calls underlying method
func (v *ServerWrapper) GetUserTokens(ctx context.Context, req *authProto.GetUserTokensRequest) (*authProto.GetUserTokensResponse, error) {
	if err := v.validateStruct(ctx, req); err != nil {
		return nil, err
	}
	return v.upstream.GetUserTokens(ctx, req)
}

// DeleteToken performs request validation and calls underlying method
func (v *ServerWrapper) DeleteToken(ctx context.Context, req *authProto.DeleteTokenRequest) (*empty.Empty, error) {
	if err := v.validateStruct(ctx, req); err != nil {
		return nil, err
	}
	return v.upstream.DeleteToken(ctx, req)
}

// DeleteUserTokens performs request validation and calls underlying method
func (v *ServerWrapper) DeleteUserTokens(ctx context.Context, req *authProto.DeleteUserTokensRequest) (*empty.Empty, error) {
	if err := v.validateStruct(ctx, req); err != nil {
		return nil, err
	}
	return v.upstream.DeleteUserTokens(ctx, req)
}
