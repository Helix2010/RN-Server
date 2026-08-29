package api

import "testing"

func TestInstallationCredentialIsRandomAndHasHash(t *testing.T) {
	credential, hash, err := newInstallationCredential()
	if err != nil || len(credential) < 40 || len(hash) != 64 {
		t.Fatalf("invalid credential: %q %q %v", credential, hash, err)
	}
	other, _, _ := newInstallationCredential()
	if credential == other {
		t.Fatal("installation credentials must be random")
	}
}
