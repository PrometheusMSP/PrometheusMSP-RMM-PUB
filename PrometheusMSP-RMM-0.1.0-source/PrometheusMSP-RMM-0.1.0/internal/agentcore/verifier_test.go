package agentcore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PrometheusMSP/PrometheusMSP-RMM/internal/protocol"
)

func signedTestJob(t *testing.T, private ed25519.PrivateKey, now time.Time) protocol.JobEnvelope {
	t.Helper()
	j := protocol.JobEnvelope{ID: "job-1", TenantID: "tenant-1", DeviceID: "device-1", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Nonce: "nonce-1", Action: ActionServiceRestart, Parameters: json.RawMessage(`{"service_name":"ssh"}`), Risk: "high", ApprovedBy: "tech-1"}
	if err := j.Sign(private); err != nil { t.Fatal(err) }
	return j
}

func TestJobVerifierChecksSignatureScopeAndReplay(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	replay, err := LoadReplayStore(filepath.Join(t.TempDir(), "replay.json"))
	if err != nil { t.Fatal(err) }
	v, err := NewJobVerifier(base64.RawURLEncoding.EncodeToString(public), "tenant-1", "device-1", replay)
	if err != nil { t.Fatal(err) }
	v.now = func() time.Time { return now }
	j := signedTestJob(t, private, now)
	if err := v.Verify(j); err != nil { t.Fatalf("valid job rejected: %v", err) }
	if err := v.Verify(j); err == nil || !strings.Contains(err.Error(), "already consumed") { t.Fatalf("expected replay rejection, got %v", err) }

	j = signedTestJob(t, private, now)
	j.Nonce = "nonce-2"
	j.DeviceID = "another-device"
	if err := j.Sign(private); err != nil { t.Fatal(err) }
	if err := v.Verify(j); err == nil || !strings.Contains(err.Error(), "scope") { t.Fatalf("expected scope rejection, got %v", err) }
}

func TestJobVerifierRejectsTamperingAndExpiry(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	replay, _ := LoadReplayStore(filepath.Join(t.TempDir(), "replay.json"))
	v, _ := NewJobVerifier(base64.RawURLEncoding.EncodeToString(public), "tenant-1", "device-1", replay)
	v.now = func() time.Time { return now }
	j := signedTestJob(t, private, now)
	j.Action = ActionControlledReboot
	if err := v.Verify(j); err == nil || !strings.Contains(err.Error(), "signature") { t.Fatalf("expected signature rejection, got %v", err) }
	j = signedTestJob(t, private, now)
	j.ExpiresAt = now.Add(-time.Second)
	if err := v.Verify(j); err == nil || !strings.Contains(err.Error(), "expired") { t.Fatalf("expected expiry rejection, got %v", err) }
}
