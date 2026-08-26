package objectstore

import (
	"context"
	"net/url"
	"testing"
	"time"
)

func TestRejectsIncompleteOrInvalidStorageConfiguration(t *testing.T) {
	factory := AWSFactory{}
	if _, err := factory.New(Config{Region: "us-east-1", Bucket: "bucket", AccessKeyID: "only-access"}); err == nil {
		t.Fatal("expected incomplete credentials to be rejected")
	}
	if _, err := factory.New(Config{Region: "us-east-1", Bucket: "bucket", AccessKeyID: "access", SecretAccessKey: "secret", Endpoint: "not-a-url"}); err == nil {
		t.Fatal("expected invalid endpoint to be rejected")
	}
}

func TestPresignGetDoesNotRequestOptionalResponseChecksum(t *testing.T) {
	factory := AWSFactory{}
	client, err := factory.New(Config{
		Endpoint:        "https://obs.example.test",
		Region:          "ap-southeast-3",
		Bucket:          "bucket",
		AccessKeyID:     "access",
		SecretAccessKey: "secret",
	})
	if err != nil {
		t.Fatalf("create storage client: %v", err)
	}

	downloader, ok := client.(*s3Client)
	if !ok {
		t.Fatalf("expected AWS storage client, got %T", client)
	}
	downloadURL, err := downloader.PresignGet(
		context.Background(),
		"tenants/tenant/releases/release/application.apk",
		5*time.Minute,
		"application.apk",
	)
	if err != nil {
		t.Fatalf("presign download: %v", err)
	}
	parsed, err := url.Parse(downloadURL)
	if err != nil {
		t.Fatalf("parse presigned URL: %v", err)
	}
	if got := parsed.Query().Get("X-Amz-Checksum-Mode"); got != "" {
		t.Fatalf("optional response checksum mode must not be signed, got %q", got)
	}
}
