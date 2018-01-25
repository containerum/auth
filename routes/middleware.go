package routes

import (
	"net/http"
	"strings"

	"git.containerum.net/ch/json-types/errors"
	umtypes "git.containerum.net/ch/json-types/user-manager"
	"github.com/gin-gonic/gin"
	"gopkg.in/go-playground/validator.v8"
)

var headerValidationMap = map[string]string{
	umtypes.UserIDHeader:      "uuid4",
	umtypes.ClientIPHeader:    "ip",
	umtypes.PartTokenIDHeader: "uuid4",
}

var validate = validator.New(&validator.Config{})

func validateHeaders(ctx *gin.Context) {
	var errs []string

	for headerKey, validateTag := range headerValidationMap {
		if headerValue := ctx.GetHeader(headerKey); headerValue != "" {
			if verr := validate.Field(headerValue, validateTag); verr != nil {
				errs = append(errs, verr.Error())
			}
		}
	}

	if len(errs) > 0 {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, errors.New(strings.Join(errs, ";")))
	}
}

func requireHeaders(headers ...string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var missingHeaders []string

		for _, headerKey := range headers {
			if headerValue := ctx.GetHeader(headerKey); headerValue == "" {
				missingHeaders = append(missingHeaders, headerKey)
			}
		}

		if len(missingHeaders) > 0 {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, errors.Format("missing required headers %v", missingHeaders))
		}
	}
}

func validateURLParam(paramName, validationTag string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if verr := validate.Field(paramName, validationTag); verr != nil {
			ctx.AbortWithStatusJSON(http.StatusBadRequest, errors.New(verr.Error()))
		}
	}
}
