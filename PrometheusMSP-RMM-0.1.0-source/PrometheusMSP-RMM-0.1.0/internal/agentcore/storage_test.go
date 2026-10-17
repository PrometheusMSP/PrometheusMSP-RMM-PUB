package agentcore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestIdentitySavedWithRestrictedPermissions(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state", "identity.json")
	id := &Identity{DeviceID: "d", TenantID: "t", PrivateKeyPEM: "private", CertificatePEM: "cert", ServerSigningKey: "key"}
	if e := SaveIdentity(p, id); e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(p)
	if e != nil {
		t.Fatal(e)
	}
	if err := checkIdentityPermissions(p, info.Mode()); err != nil {
		t.Fatal(err)
	}
}

func TestSpoolIsBoundedAndOrdered(t *testing.T) {
	s, e := NewSpool(t.TempDir(), 160)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 10; i++ {
		if e = s.Enqueue("heartbeat", map[string]int{"sequence": i}); e != nil {
			t.Fatal(e)
		}
	}
	var seen []int
	e = s.Drain(func(item SpoolItem) error {
		var v map[string]int
		if e := json.Unmarshal(item.Body, &v); e != nil {
			return e
		}
		seen = append(seen, v["sequence"])
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if len(seen) == 0 || len(seen) >= 10 {
		t.Fatalf("expected bounded retained items, got %v", seen)
	}
	for i := 1; i < len(seen); i++ {
		if seen[i] <= seen[i-1] {
			t.Fatalf("items out of order: %v", seen)
		}
	}
}
