package objectstore

import "testing"

func TestRejectsIncompleteOrInvalidStorageConfiguration(t *testing.T) {
	factory := AWSFactory{}
	if _, err := factory.New(Config{Region: "us-east-1", Bucket: "bucket", AccessKeyID: "only-access"}); err == nil {
		t.Fatal("expected incomplete credentials to be rejected")
	}
	if _, err := factory.New(Config{Region: "us-east-1", Bucket: "bucket", AccessKeyID: "access", SecretAccessKey: "secret", Endpoint: "not-a-url"}); err == nil {
		t.Fatal("expected invalid endpoint to be rejected")
	}
}
