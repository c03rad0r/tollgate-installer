package app

import (
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestWiFiProbeDoesNotBlindlyRetryEmptyRootPassword(t *testing.T) {
	oldConnect, oldAllowed := sshConnectForWiFiTest, emptyPasswordAllowedForWiFiTest
	t.Cleanup(func() {
		sshConnectForWiFiTest = oldConnect
		emptyPasswordAllowedForWiFiTest = oldAllowed
	})

	var attempts []string
	sshConnectForWiFiTest = func(_, password string) *ssh.Client {
		attempts = append(attempts, password)
		return nil
	}
	emptyPasswordAllowedForWiFiTest = func(string) bool { return false }

	ok, _ := testSTAConfig("192.0.2.1", "root-password", "bad-ssid", "wrongpass", "")
	if ok {
		t.Fatal("a nil SSH client must make the probe fail")
	}
	if len(attempts) != 1 || attempts[0] != "root-password" {
		t.Fatalf("a password-protected router must not get an empty-password retry: %v", attempts)
	}
}

func TestWiFiProbeOnlyRetriesBlankPasswordForVanillaRouters(t *testing.T) {
	oldConnect, oldAllowed := sshConnectForWiFiTest, emptyPasswordAllowedForWiFiTest
	t.Cleanup(func() {
		sshConnectForWiFiTest = oldConnect
		emptyPasswordAllowedForWiFiTest = oldAllowed
	})

	var attempts []string
	sshConnectForWiFiTest = func(_, password string) *ssh.Client {
		attempts = append(attempts, password)
		return nil
	}
	emptyPasswordAllowedForWiFiTest = func(string) bool { return true }

	testSTAConfig("192.0.2.1", "root-password", "bad-ssid", "wrongpass", "")
	if len(attempts) != 2 || attempts[0] != "root-password" || attempts[1] != "" {
		t.Fatalf("a vanilla-only blank retry should happen exactly once: %v", attempts)
	}
}
