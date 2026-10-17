package agentcore

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PrometheusMSP/PrometheusMSP-RMM/internal/protocol"
)

type fakeExecutor struct {
	service string
	reboot  time.Duration
	dry     bool
}

func (f *fakeExecutor) RestartService(_ context.Context, name string, dry bool) (string, error) {
	f.service = name
	f.dry = dry
	return "ok", nil
}
func (f *fakeExecutor) Reboot(_ context.Context, delay time.Duration, dry bool) (string, error) {
	f.reboot = delay
	f.dry = dry
	return "ok", nil
}
func (f *fakeExecutor) InstallSoftware(context.Context, string, string, bool) (string, error) {
	return "ok", nil
}
func (f *fakeExecutor) RemoveSoftware(context.Context, string, bool) (string, error) {
	return "ok", nil
}
func (f *fakeExecutor) InstallPatches(context.Context, []string, bool) (string, error) {
	return "ok", nil
}

func TestPolicyDefaultsDenyAndRequiresApproval(t *testing.T) {
	p := NewPolicy(Config{AllowedServices: []string{"ssh"}, DryRun: true})
	x := &fakeExecutor{}
	j := protocol.JobEnvelope{Action: ActionServiceRestart, Risk: "medium", Parameters: json.RawMessage(`{"service_name":"ssh"}`)}
	if _, e := p.Execute(context.Background(), x, j); e == nil || !strings.Contains(e.Error(), "approval") {
		t.Fatalf("expected approval rejection, got %v", e)
	}
	j.ApprovedBy = "tech"
	j.Parameters = json.RawMessage(`{"service_name":"not-allowed"}`)
	if _, e := p.Execute(context.Background(), x, j); e == nil || !strings.Contains(e.Error(), "allowlisted") {
		t.Fatalf("expected allowlist rejection, got %v", e)
	}
	j.Parameters = json.RawMessage(`{"service_name":"ssh","command":"evil"}`)
	if _, e := p.Execute(context.Background(), x, j); e == nil || !strings.Contains(e.Error(), "unknown field") {
		t.Fatalf("expected unknown parameter rejection, got %v", e)
	}
}

func TestPolicyExecutesAllowlistedServiceAsDryRun(t *testing.T) {
	p := NewPolicy(Config{AllowedServices: []string{"ssh"}, DryRun: true})
	x := &fakeExecutor{}
	j := protocol.JobEnvelope{Action: ActionServiceRestart, Risk: "medium", ApprovedBy: "tech", Parameters: json.RawMessage(`{"service_name":"ssh"}`)}
	if _, e := p.Execute(context.Background(), x, j); e != nil {
		t.Fatal(e)
	}
	if x.service != "ssh" || !x.dry {
		t.Fatalf("unexpected execution: %#v", x)
	}
}

func TestSoftwarePolicyRequiresLocalEnablementAndAllowlist(t *testing.T) {
	x := &fakeExecutor{}
	j := protocol.JobEnvelope{Action: ActionSoftwareInstall, Risk: "high", ApprovedBy: "tech", Parameters: json.RawMessage(`{"package_name":"curl"}`)}
	p := NewPolicy(Config{AllowedPackages: []string{"curl"}, DryRun: true})
	if _, e := p.Execute(context.Background(), x, j); e == nil || !strings.Contains(e.Error(), "disabled") {
		t.Fatalf("expected disabled rejection, got %v", e)
	}
	p = NewPolicy(Config{AllowSoftware: true, AllowedPackages: []string{"curl"}, DryRun: true})
	j.Parameters = json.RawMessage(`{"package_name":"curl;rm"}`)
	if _, e := p.Execute(context.Background(), x, j); e == nil || !strings.Contains(e.Error(), "invalid package") {
		t.Fatalf("expected invalid package rejection, got %v", e)
	}
	j.Parameters = json.RawMessage(`{"package_name":"wget"}`)
	if _, e := p.Execute(context.Background(), x, j); e == nil || !strings.Contains(e.Error(), "allowlisted") {
		t.Fatalf("expected package allowlist rejection, got %v", e)
	}
}

func TestCleanupDoesNotFollowSymlinksAndHonorsAge(t *testing.T) {
	d := t.TempDir()
	old := filepath.Join(d, "old.tmp")
	fresh := filepath.Join(d, "fresh.tmp")
	outside := filepath.Join(t.TempDir(), "outside")
	for _, p := range []string{old, fresh, outside} {
		if e := os.WriteFile(p, []byte("x"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	past := time.Now().Add(-48 * time.Hour)
	if e := os.Chtimes(old, past, past); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(outside, filepath.Join(d, "link")); e != nil {
		t.Fatal(e)
	}
	if _, e := cleanupTemp(d, time.Now().Add(-24*time.Hour), false); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(old); !os.IsNotExist(e) {
		t.Fatalf("old file was not removed")
	}
	if _, e := os.Stat(fresh); e != nil {
		t.Fatalf("fresh file removed: %v", e)
	}
	if _, e := os.Stat(outside); e != nil {
		t.Fatalf("symlink target removed: %v", e)
	}
}
