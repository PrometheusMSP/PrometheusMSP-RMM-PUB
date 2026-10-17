package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/PrometheusMSP/PrometheusMSP-RMM/internal/agentcore"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := runPlatform(logger); err != nil {
		logger.Error("agent stopped", "error", err)
		os.Exit(1)
	}
}

// runAgent is used by both the interactive CLI and Windows service.
func runAgent(ctx context.Context, logger *slog.Logger) error {
	cfg, err := agentcore.ConfigFromEnv()
	if err != nil {
		return fmt.Errorf("invalid agent configuration: %w", err)
	}
	agent, err := agentcore.NewAgent(ctx, cfg, logger)
	if err != nil {
		return fmt.Errorf("agent initialization failed: %w", err)
	}
	logger.Info("agent started", "version", agentcore.AgentVersion)
	if err := agent.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("agent run failed: %w", err)
	}
	return nil
}
