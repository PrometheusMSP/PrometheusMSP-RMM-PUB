//go:build windows

package agentcore

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/windows"
)

// restrictIdentityPermissions uses Windows NTFS DACLs, not os.Chmod.
// When run as the installed LocalSystem service, the allowed identities
// are SYSTEM and BUILTIN\Administrators. When a non-SYSTEM developer runs
// tests, the current process user is also allowed for test cleanup.
func restrictIdentityPermissions(path string, directory bool) error {
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("query current Windows identity: %w", err)
	}
	sid := tokenUser.User.Sid.String()
	flags := ""
	if directory {
		flags = "OICI"
	}
	sddl := fmt.Sprintf("D:P(A;%s;FA;;;SY)(A;%s;FA;;;BA)", flags, flags)
	if sid != "S-1-5-18" {
		sddl += fmt.Sprintf("(A;%s;FA;;;%s)", flags, sid)
	}

	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("build Windows DACL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read Windows DACL: %w", err)
	}
	if dacl == nil {
		return fmt.Errorf("refusing to apply a null Windows DACL")
	}
	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
	runtime.KeepAlive(sd)
	if err != nil {
		return fmt.Errorf("set protected Windows DACL on %q: %w", path, err)
	}
	return nil
}
