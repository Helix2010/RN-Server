package objectstore

import "testing"

func TestProviderList(t *testing.T) {
	if !KnownProvider("obs") || KnownProvider("oss") {
		t.Error("provider list is wrong")
	}
	if !ProviderNeedsEndpoint("obs") || ProviderNeedsEndpoint("s3") {
		t.Error("only providers without a default address must require an endpoint")
	}
}
