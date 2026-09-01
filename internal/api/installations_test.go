package api

import (
	"strings"
	"testing"
)

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

func TestInstallationUpsertPlaceholderCount(t *testing.T) {
	head := installationUpsertSQL[:strings.Index(installationUpsertSQL, " ON DUPLICATE")]
	columns := head[strings.Index(head, "(")+1 : strings.Index(head, ")")]
	values := head[strings.LastIndex(head, "(")+1 : strings.LastIndex(head, ")")]
	columnCount, valueCount := len(strings.Split(columns, ",")), len(strings.Split(values, ","))
	if columnCount != valueCount {
		t.Fatalf("app_installations upsert lists %d columns but %d values", columnCount, valueCount)
	}
	if got := strings.Count(values, "?"); got != columnCount-1 {
		t.Fatalf("app_installations upsert expects %d placeholders (all columns except the status literal), got %d", columnCount-1, got)
	}
}
