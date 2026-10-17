//go:build linux

package agentcore

import (
	"reflect"
	"testing"
)

func TestPackageArgsUseDirectNativeOperations(t *testing.T) {
	tests := []struct {
		name, manager, operation string
		packages, want           []string
	}{
		{name: "apt patch", manager: "/usr/bin/apt-get", operation: "patch", packages: []string{"openssl"}, want: []string{"-y", "--only-upgrade", "install", "openssl"}},
		{name: "dnf install", manager: "/usr/bin/dnf", operation: "install", packages: []string{"curl"}, want: []string{"-y", "install", "curl"}},
		{name: "zypper remove", manager: "/usr/bin/zypper", operation: "remove", packages: []string{"curl"}, want: []string{"--non-interactive", "remove", "curl"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := packageArgs(tt.manager, tt.operation, tt.packages); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("packageArgs()=%v, want %v", got, tt.want)
			}
		})
	}
}

func TestProcessInventoryIsBounded(t *testing.T) {
	if got := linuxProcesses(); len(got) > 500 {
		t.Fatalf("got %d processes, cap is 500", len(got))
	}
}
