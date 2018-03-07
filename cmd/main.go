package cmd

import (
	"fmt"

	"os"

	"os/signal"

	"git.containerum.net/ch/auth/pkg/validation"
	"git.containerum.net/ch/kube-client/pkg/cherry/auth"
	"github.com/gin-gonic/gin/binding"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

//go:generate protoc --go_out=plugins=grpc:../proto -I../proto auth.proto auth_types.proto uuid.proto
//go:generate protoc-go-inject-tag -input=../proto/auth.pb.go
//go:generate protoc-go-inject-tag -input=../proto/auth_types.pb.go
//go:generate protoc-go-inject-tag -input=../proto/uuid.pb.go

func logExit(err error) {
	if err != nil {
		logrus.WithError(err).Fatalf("Setup error")
		os.Exit(1)
	}
}

func main() {
	viper.SetEnvPrefix("ch_auth")
	viper.AutomaticEnv()

	if err := logLevelSetup(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if err := logModeSetup(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	viper.SetDefault("http_listenaddr", ":8080")
	httpTracer, err := getTracer(viper.GetString("http_listenaddr"), "ch-auth-rest")
	logExit(err)

	viper.SetDefault("grpc_listenaddr", ":8888")
	grpcTracer, err := getTracer(viper.GetString("grpc_listenaddr"), "ch-auth-grpc")
	logExit(err)

	storage, err := getStorage()
	logExit(err)

	validator := validation.StandardAuthValidator(setupTranslator())
	binding.Validator = &validation.GinValidatorV9{Validate: validator}

	// wrap with validation proxy
	storage = validation.NewServerWrapper(storage, validator, autherr.ErrValidation)

	servers := []Server{
		NewHTTPServer(viper.GetString("http_listenaddr"), httpTracer, storage),
		NewGRPCServer(viper.GetString("grpc_listenaddr"), grpcTracer, storage),
	}

	RunServers(servers...)

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	<-quit
	StopServers(servers...)
}
