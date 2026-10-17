//go:build windows

package agentcore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func checkIdentityPermissions(path string, _ os.FileMode) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read file Windows ACL: %w", err)
	}
	got := sd.String()
	if !strings.Contains(got, "D:P") {
		return fmt.Errorf("identity DACL is not protected: %s", got)
	}
	for _, required := range []string{";;;SY)", ";;;BA)"} {
		if !strings.Contains(got, required) {
			return fmt.Errorf("identity DACL missing %q: %s", required, got)
		}
	}
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sid := tokenUser.User.Sid.String()
	expectedACEs := 2
	if sid != "S-1-5-18" {
		expectedACEs++
		if !strings.Contains(got, ";;;"+sid+")") {
			return fmt.Errorf("identity DACL missing agent/test process identity: %s", got)
		}
	}
	if count := strings.Count(got, "("); count != expectedACEs {
		return fmt.Errorf("identity DACL contains unexpected ACEs (got %d, want %d): %s", count, expectedACEs, got)
	}
	return nil
}

func TestIdentityCanBeReplacedWithRestrictedACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "identity.json")
	id := &Identity{DeviceID: "d", TenantID: "t", PrivateKeyPEM: "private", CertificatePEM: "cert", ServerSigningKey: "key"}
	for i := 0; i < 2; i++ {
		if err := SaveIdentity(path, id); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkIdentityPermissions(path, info.Mode()); err != nil {
			t.Fatal(err)
		}
	}
}
