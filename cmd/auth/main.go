package main

import (
	"os"
	"os/signal"
	"text/tabwriter"

	"fmt"

	"git.containerum.net/ch/auth/pkg/errors"
	"git.containerum.net/ch/auth/pkg/utils"
	"git.containerum.net/ch/auth/pkg/validation"
	"github.com/gin-gonic/gin/binding"
	"github.com/sirupsen/logrus"
	"gopkg.in/urfave/cli.v2"
)

//go:generate protoc --go_out=plugins=grpc:../../proto -I../../proto auth.proto auth_types.proto
//go:generate protoc-go-inject-tag -input=../../proto/auth.pb.go
//go:generate protoc-go-inject-tag -input=../../proto/auth_types.pb.go
//go:generate swagger generate spec -m -i ../../swagger-basic.yml -o ../../swagger.json

func logExit(err error) {
	if err != nil {
		logrus.WithError(err).Fatalf("Setup error")
		os.Exit(1)
	}
}

const serversContextKey = "servers"

func prettyPrintFlags(ctx *cli.Context) {
	fmt.Printf("Starting %v %v\n", ctx.App.Name, ctx.App.Version)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.TabIndent|tabwriter.Debug)
	for _, f := range ctx.App.VisibleFlags() {
		fmt.Fprintf(w, "Flag: %s\t Value: %v\n", f.Names()[0], ctx.Generic(f.Names()[0]))
	}
	w.Flush()
}

func main() {
	app := cli.App{
		Name:        "auth",
		Description: "Authorization (token management) service for Container hosting",
		Version:     utils.VERSION,
		Flags: []cli.Flag{
			// logging
			&LogLevelFlag,
			&LogModeFlag,
			// tokens factory
			&TokensFlag,
			&JWTSigningMethodFlag,
			&IssuerFlag,
			&AccessTokenLifeTimeFlag,
			&RefreshTokenLifeTimeFlag,
			&JWTSigningKeyFileFlag,
			&JWTValidationKeyFileFlag,
			// tokens storage
			&StorageFlag,
			&BuntStorageFileFlag,
			&BuntSyncPolicyFlag,
			&BuntAutoShrinkDisabledFlag,
			&BuntAutoShrinkMinSizeFlag,
			&BuntAutoShrinkPercentageFlag,
			// opentracing
			&TracerFlag,
			&ZipkinCollectorFlag,
			&ZipkinHTTPCollectorURLFlag,
			&ZipkinKafkaCollectorAddrsFlag,
			&ZipkinScribeCollectorAddrFlag,
			&ZipkinScribeCollectorDurationFlag,
			&ZipkinRecorderDebugFlag,
			// listening
			&HTTPListenAddrFlag,
			&GRPCListenAddrFlag,
			// other
			&CORSFlag,
		},
		Before: func(ctx *cli.Context) error {
			prettyPrintFlags(ctx)

			if err := logLevelSetup(ctx); err != nil {
				return err
			}

			if err := logModeSetup(ctx); err != nil {
				return err
			}

			httpListenAddr := ctx.String(HTTPListenAddrFlag.Name)
			grpcListenAddr := ctx.String(GRPCListenAddrFlag.Name)

			httpTracer, err := getTracer(ctx, httpListenAddr, "ch-auth-rest")
			if err != nil {
				return err
			}

			grpcTracer, err := getTracer(ctx, grpcListenAddr, "ch-auth-grpc")
			if err != nil {
				return err
			}

			storage, err := getStorage(ctx)
			if err != nil {
				return err
			}

			translator := setupTranslator()

			validator := validation.StandardAuthValidator(translator)
			binding.Validator = &validation.GinValidatorV9{Validate: validator}

			// wrap with validation proxy
			storage = validation.NewServerWrapper(storage, validator, translator, autherr.ErrValidation)

			servers := []Server{
				NewHTTPServer(httpListenAddr, httpTracer, storage, ctx.Bool(CORSFlag.Name)),
				NewGRPCServer(grpcListenAddr, grpcTracer, storage),
			}

			ctx.App.Metadata[serversContextKey] = servers

			return nil
		},
		Action: func(ctx *cli.Context) error {
			servers := ctx.App.Metadata[serversContextKey].([]Server)

			RunServers(servers...)

			quit := make(chan os.Signal)
			signal.Notify(quit, os.Interrupt)
			<-quit
			StopServers(servers...)

			return nil
		},
	}

	logExit(app.Run(os.Args))
}
