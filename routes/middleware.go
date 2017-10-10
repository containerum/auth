package routes

import (
	"net/http"

	"bytes"
	"fmt"
	"io/ioutil"

	"bitbucket.org/exonch/ch-grpc/auth"
	"github.com/husobee/vestigo"
	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/ext"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)

// Middleware for opentracing functionality. MUST BE FIRST in chain
func newOpenTracingMiddleware(tracer opentracing.Tracer, operationName string) vestigo.Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			wireContext, err := tracer.Extract(
				opentracing.TextMap,
				opentracing.HTTPHeadersCarrier(r.Header),
			)
			if err != nil {
				logrus.Printf("Opentracing span extract: %v", err)
			}

			span := tracer.StartSpan(operationName, ext.RPCServerOption(wireContext))
			defer span.Finish()

			ctx := opentracing.ContextWithSpan(r.Context(), span)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
	}
}

// Middleware injecting storage interface to context. MUST BE INCLUDED if storage used in handler
func newStorageInjectionMiddleware(storage auth.AuthServer) vestigo.Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), authServerContextKey, storage)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
	}
}

// name -> function validating value
type validators map[string](func(value string) error)

func newHeaderValidationMiddleware(validators validators) vestigo.Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			validationErrors := make(map[string]error) // header name to error

			for headerName, validator := range validators {
				headerValue := r.Header.Get(headerName)
				if headerValue != "" {
					if err := validator(headerValue); err != nil {
						validationErrors[headerName] = err
					}
				}
			}

			if len(validationErrors) != 0 {
				var errs []string
				for header, err := range validationErrors {
					errs = append(errs, fmt.Sprintf("Invalid header %s: %v", header, err))
				}
				sendErrorsWithCode(w, errs, http.StatusBadRequest)
				return
			}

			next(w, r)
		}
	}
}

func newParameterValidationMiddleware(validators validators) vestigo.Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			validationErrors := make(map[string]error) // param name to error

			for paramName, validator := range validators {
				paramValue := vestigo.Param(r, paramName)
				if paramValue != "" {
					if err := validator(paramValue); err != nil {
						validationErrors[paramName] = err
					}
				}
			}

			if len(validationErrors) != 0 {
				var errs []string
				for header, err := range validationErrors {
					errs = append(errs, fmt.Sprintf("Invalid parameter %s: %v\n", header, err))
				}
				sendErrorsWithCode(w, errs, http.StatusBadRequest)
				return
			}

			next(w, r)
		}
	}
}

func newBodyValidationMiddleware(validator func(body []byte) error) vestigo.Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "", http.StatusInternalServerError)
			}
			r.Body.Close()

			if err := validator(body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
			next(w, r)
		}
	}
}
