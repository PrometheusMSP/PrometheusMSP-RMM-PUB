package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"

	"github.com/PrometheusMSP/PrometheusMSP-RMM/internal/agentcore"
)

func main(){
	log:=slog.New(slog.NewJSONHandler(os.Stdout,nil));cfg,e:=agentcore.ConfigFromEnv();if e!=nil{log.Error("invalid configuration","error",e);os.Exit(2)}
	ctx,stop:=signal.NotifyContext(context.Background(),os.Interrupt);defer stop();a,e:=agentcore.NewAgent(ctx,cfg,log);if e!=nil{log.Error("agent initialization failed","error",e);os.Exit(1)};log.Info("agent started","version",agentcore.AgentVersion);if e=a.Run(ctx);e!=nil&&!errors.Is(e,context.Canceled){log.Error("agent stopped","error",e);os.Exit(1)}
}
