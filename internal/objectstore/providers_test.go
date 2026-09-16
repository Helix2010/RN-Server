package objectstore

import "testing"

func TestPermissionNamesFollowTheProvider(t *testing.T) {
	cases := []struct{ provider, action, want string }{
		{"obs", "PutObject", "obs:object:PutObject"},
		{"obs", "GetObject", "obs:object:GetObject"},
		{"obs", "GetBucketVersioning", "obs:bucket:GetBucketVersioning"},
		{"s3", "GetBucketVersioning", "s3:GetBucketVersioning"},
		{"minio", "PutObject", "s3:PutObject"},
	}
	for _, tc := range cases {
		if got := Permission(tc.provider, tc.action); got != tc.want {
			t.Errorf("Permission(%q, %q) = %q, want %q", tc.provider, tc.action, got, tc.want)
		}
	}
	if !KnownProvider("obs") || KnownProvider("oss") {
		t.Error("provider list is wrong")
	}
	if !ProviderNeedsEndpoint("obs") || ProviderNeedsEndpoint("s3") {
		t.Error("only providers without a default address must require an endpoint")
	}
}
