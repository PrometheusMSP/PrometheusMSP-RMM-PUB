package agentcore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigRequiresHTTPS(t *testing.T) {
	t.Setenv("PROMETHEUS_SERVER_URL", "http://control.example.test")
	if _, err := ConfigFromEnv(); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("expected HTTPS validation error, got %v", err)
	}
}

func TestBootstrapClientRejectsInvalidCA(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0600); err != nil { t.Fatal(err) }
	_, err := NewBootstrapClient(Config{ServerURL: "https://control.example.test", BootstrapCAFile: path})
	if err == nil || !strings.Contains(err.Error(), "no valid certificates") { t.Fatalf("expected invalid CA error, got %v", err) }
}
