//go:build windows

package agentcore

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/PrometheusMSP/PrometheusMSP-RMM/internal/protocol"
)

type Platform struct{}

func NewPlatform(string) *Platform { return &Platform{} }
func (p *Platform) RestartService(ctx context.Context, name string, dry bool) (string, error) {
	if dry {
		return "would restart service " + name, nil
	}
	b, e := exec.CommandContext(ctx, "sc.exe", "stop", name).CombinedOutput()
	if e == nil {
		b2, e2 := exec.CommandContext(ctx, "sc.exe", "start", name).CombinedOutput()
		b = append(b, b2...)
		e = e2
	}
	return bounded(string(b)), e
}
func (p *Platform) Reboot(ctx context.Context, delay time.Duration, dry bool) (string, error) {
	if dry {
		return fmt.Sprintf("would reboot after %s", delay), nil
	}
	b, e := exec.CommandContext(ctx, "shutdown.exe", "/r", "/t", fmt.Sprint(int(delay.Seconds())), "/d", "p:4:1", "/c", "Prometheus RMM approved reboot").CombinedOutput()
	return bounded(string(b)), e
}
func (p *Platform) InstallSoftware(context.Context, string, string, bool) (string, error) {
	return "", errors.New("software installation is not supported on Windows in this milestone")
}
func (p *Platform) RemoveSoftware(context.Context, string, bool) (string, error) {
	return "", errors.New("software removal is not supported on Windows in this milestone")
}
func (p *Platform) InstallPatches(context.Context, []string, bool) (string, error) {
	return "", errors.New("patch installation is not supported on Windows in this milestone")
}
func (p *Platform) details(ctx context.Context) (protocol.OSInfo, protocol.HardwareInfo, []protocol.DiskInfo, []protocol.ServiceInfo, []protocol.SoftwareInfo, []protocol.ProcessInfo) {
	return protocol.OSInfo{Name: "Windows", Architecture: runtimeArch()}, protocol.HardwareInfo{CPUs: runtimeCPUs()}, nil, windowsServices(ctx), windowsSoftware(ctx), windowsProcesses(ctx)
}
func windowsProcesses(ctx context.Context) []protocol.ProcessInfo {
	commandCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	b, e := exec.CommandContext(commandCtx, "tasklist.exe", "/fo", "csv", "/nh").Output()
	if e != nil {
		return nil
	}
	rows, e := csv.NewReader(bytes.NewReader(b)).ReadAll()
	if e != nil {
		return nil
	}
	var out []protocol.ProcessInfo
	for _, row := range rows {
		if len(out) >= 500 {
			break
		}
		if len(row) >= 2 {
			pid, _ := strconv.Atoi(row[1])
			out = append(out, protocol.ProcessInfo{PID: pid, Name: row[0]})
		}
	}
	return out
}
func windowsServices(ctx context.Context) []protocol.ServiceInfo {
	commandCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	b, e := exec.CommandContext(commandCtx, "sc.exe", "query", "state=", "all").Output()
	if e != nil {
		return nil
	}
	var out []protocol.ServiceInfo
	var name string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "SERVICE_NAME:") {
			name = strings.TrimSpace(strings.TrimPrefix(line, "SERVICE_NAME:"))
		} else if name != "" && strings.HasPrefix(line, "STATE") && len(out) < 500 {
			fields := strings.Fields(line)
			status := "unknown"
			if len(fields) >= 4 {
				status = strings.ToLower(fields[3])
			}
			out = append(out, protocol.ServiceInfo{Name: name, Status: status})
			name = ""
		}
	}
	return out
}
func windowsSoftware(ctx context.Context) []protocol.SoftwareInfo {
	const script = `$p=@('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'); Get-ItemProperty $p -ErrorAction SilentlyContinue | Where-Object DisplayName | Select-Object -First 500 | ForEach-Object { "$($_.DisplayName)$([char]9)$($_.DisplayVersion)$([char]9)$($_.Publisher)" }`
	commandCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	b, e := exec.CommandContext(commandCtx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if e != nil {
		return nil
	}
	var out []protocol.SoftwareInfo
	for _, line := range strings.Split(string(b), "\n") {
		if len(out) >= 500 {
			break
		}
		fields := strings.SplitN(strings.TrimSpace(line), "\t", 3)
		if len(fields) >= 2 && fields[0] != "" {
			item := protocol.SoftwareInfo{Name: fields[0], Version: fields[1]}
			if len(fields) == 3 {
				item.Publisher = fields[2]
			}
			out = append(out, item)
		}
	}
	return out
}
func (p *Platform) uptime() uint64 { return 0 }
func (p *Platform) events(ctx context.Context, deviceID string) (protocol.EventBatch, error) {
	b, e := exec.CommandContext(ctx, "wevtutil.exe", "qe", "System", "/c:50", "/rd:true", "/f:text").Output()
	if e != nil {
		return protocol.EventBatch{}, nil
	}
	msg := strings.TrimSpace(decodeWindowsEventOutput(b))
	if msg == "" {
		return protocol.EventBatch{}, nil
	}
	return protocol.EventBatch{Events: []protocol.Event{{ID: fmt.Sprint(time.Now().UnixNano()), SchemaVersion: protocol.SchemaVersion, DeviceID: deviceID, OccurredAt: time.Now().UTC(), Source: "windows-event-log", Severity: "info", Provider: "System", Message: bounded(msg)}}}, nil
}

var _ = os.PathSeparator
