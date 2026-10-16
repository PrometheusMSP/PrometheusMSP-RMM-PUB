package security

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/PrometheusMSP/PrometheusMSP-RMM/internal/protocol"
)

func TestJobSignerUsesProtocolCanonicalSignature(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed { seed[i] = byte(i) }
	signer, err := NewJobSigner(ed25519.NewKeyFromSeed(seed))
	if err != nil { t.Fatal(err) }
	envelope := protocol.JobEnvelope{ID:"job-1",TenantID:"tenant-1",DeviceID:"device-1",IssuedAt:time.Unix(100,0).UTC(),ExpiresAt:time.Unix(200,0).UTC(),Nonce:"nonce-1",Action:"service.restart",Parameters:json.RawMessage(`{"service_name":"spooler"}`),Risk:"medium",ApprovedBy:"operator-1"}
	if err := signer.Sign(&envelope); err != nil { t.Fatal(err) }
	if err := envelope.Verify(signer.public); err != nil { t.Fatalf("protocol rejected server signature: %v",err) }
	envelope.DeviceID="device-2"
	if err := envelope.Verify(signer.public); err == nil { t.Fatal("tampered job signature was accepted") }
}
