//go:build windows

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows/svc"
)

const windowsServiceName = "PrometheusRMMAgent"

func runPlatform(logger *slog.Logger) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return fmt.Errorf("detect Windows service: %w", err)
	}
	if !isService {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runAgent(ctx, logger)
	}

	stateDir := os.Getenv("PROMETHEUS_STATE_DIR")
	if stateDir == "" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			return fmt.Errorf("PROMETHEUS_STATE_DIR and ProgramData are not set")
		}
		stateDir = filepath.Join(programData, "PrometheusRMM")
	}
	// The installer must have already restricted this directory's NTFS ACL.
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return fmt.Errorf("open service log directory: %w", err)
	}
	logFile, err := os.OpenFile(filepath.Join(stateDir, "agent.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("open service log: %w", err)
	}
	defer logFile.Close()

	serviceLogger := slog.New(slog.NewJSONHandler(logFile, nil))
	serviceLogger.Info("Windows service starting")
	return svc.Run(windowsServiceName, &agentService{logger: serviceLogger})
}

type agentService struct {
	logger *slog.Logger
}

func (a *agentService) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runAgent(ctx, a.logger)
	}()

	current := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	status <- current
	for {
		select {
		case request, ok := <-requests:
			if !ok {
				cancel()
				return false, 1
			}
			switch request.Cmd {
			case svc.Interrogate:
				status <- current
			case svc.Stop, svc.Shutdown:
				current = svc.Status{State: svc.StopPending}
				status <- current
				cancel()
				select {
				case err := <-done:
					if err != nil {
						a.logger.Error("agent shutdown failed", "error", err)
						return false, 1
					}
					return false, 0
				case <-time.After(30 * time.Second):
					a.logger.Error("agent did not stop within 30 seconds")
					return false, 1
				}
			}
		case err := <-done:
			if err != nil {
				a.logger.Error("agent exited with error", "error", err)
				return false, 1
			}
			return false, 0
		}
	}
}
