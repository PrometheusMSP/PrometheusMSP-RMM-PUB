package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestJobEnvelopeSignAndVerify(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	job := JobEnvelope{
		ID: "job-1", TenantID: "tenant-1", DeviceID: "device-1",
		IssuedAt: time.Unix(100, 0).UTC(), ExpiresAt: time.Unix(200, 0).UTC(),
		Nonce: "nonce-1", Action: "service.restart", Risk: "routine",
		Parameters: json.RawMessage(`{"service":"spooler"}`),
	}
	if err := job.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	if err := job.Verify(publicKey); err != nil {
		t.Fatalf("verify signed job: %v", err)
	}
	job.DeviceID = "other-device"
	if err := job.Verify(publicKey); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected invalid signature after tampering, got %v", err)
	}
}
