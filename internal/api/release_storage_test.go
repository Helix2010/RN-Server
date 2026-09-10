package api

import (
	"errors"
	"testing"
)

func TestValidateReleaseStorageWriteRequiresHTTPSInProduction(t *testing.T) {
	base := releaseStorageWrite{Provider: "minio", Region: "us-east-1", Bucket: "releases"}
	plain := base
	plain.Endpoint = "http://minio.internal:9000"
	if err := validateReleaseStorageWrite(plain, false); err != nil {
		t.Fatalf("development may use http endpoints: %v", err)
	}
	if err := validateReleaseStorageWrite(plain, true); !errors.Is(err, errStorageEndpointInsecure) {
		t.Fatalf("production must refuse http endpoints, got %v", err)
	}
	publicPlain := base
	publicPlain.PublicBaseURL = "http://cdn.example.com"
	if err := validateReleaseStorageWrite(publicPlain, true); !errors.Is(err, errStorageEndpointInsecure) {
		t.Fatalf("production must refuse http publicBaseUrl, got %v", err)
	}
	secure := base
	secure.Endpoint, secure.PublicBaseURL = "https://s3.example.com", "https://cdn.example.com"
	if err := validateReleaseStorageWrite(secure, true); err != nil {
		t.Fatalf("https endpoints must pass: %v", err)
	}
	if err := validateReleaseStorageWrite(base, true); err != nil {
		t.Fatalf("provider default endpoint (no endpoint given) must pass: %v", err)
	}
	garbage := base
	garbage.Endpoint = "not a url"
	if err := validateReleaseStorageWrite(garbage, true); err == nil || errors.Is(err, errStorageEndpointInsecure) {
		t.Fatalf("malformed URL must be a generic validation error, got %v", err)
	}
}

func TestStorageEndpointInsecureOnlyBitesInProduction(t *testing.T) {
	stored := storedReleaseStorage{Provider: "minio", Endpoint: "http://minio.internal:9000"}
	if storageEndpointInsecure(stored, false) {
		t.Fatal("development keeps working with http storage")
	}
	if !storageEndpointInsecure(stored, true) {
		t.Fatal("an existing http endpoint must be refused in production")
	}
	if storageEndpointInsecure(storedReleaseStorage{Provider: "s3", Endpoint: "https://s3.example.com"}, true) {
		t.Fatal("https endpoint must be accepted")
	}
	if !storageEndpointInsecure(storedReleaseStorage{Provider: "s3", PublicBaseURL: "http://cdn.example.com"}, true) {
		t.Fatal("http publicBaseUrl must be refused in production")
	}
}
