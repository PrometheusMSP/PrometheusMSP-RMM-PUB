//go:build !windows

package agentcore

import "os"

func restrictIdentityPermissions(path string, directory bool) error {
	if directory {
		return os.Chmod(path, 0700)
	}
	return os.Chmod(path, 0600)
}
