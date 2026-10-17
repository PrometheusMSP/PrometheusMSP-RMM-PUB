//go:build !windows

package agentcore

import (
	"fmt"
	"os"
)

func checkIdentityPermissions(_ string, mode os.FileMode) error {
	if mode.Perm() != 0600 {
		return fmt.Errorf("identity mode = %o, want 0600", mode.Perm())
	}
	return nil
}
