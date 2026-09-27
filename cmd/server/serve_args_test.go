package main

import (
	"testing"

	"github.com/Helix2010/RN-Server/internal/api"
)

func TestParseServeArgs(t *testing.T) {
	for _, tc := range []struct {
		args []string
		role api.Role
		port string
		bad  bool
	}{
		{nil, api.RoleAll, "13080", false},
		{[]string{"app"}, api.RoleApp, "13080", false},
		{[]string{"tenant", "--port", "13082"}, api.RoleTenant, "13082", false},
		{[]string{"platform", "--port", "13080"}, api.RolePlatform, "13080", false},
		{[]string{"admin"}, api.RoleAll, "", true},
		{[]string{"app", "--port"}, api.RoleAll, "", true},
		{[]string{"app", "--port", "0"}, api.RoleAll, "", true},
		{[]string{"app", "--port", "http"}, api.RoleAll, "", true},
		{[]string{"app", "13081"}, api.RoleAll, "", true},
	} {
		role, port, err := parseServeArgs(tc.args, "13080")
		if (err != nil) != tc.bad || role != tc.role || port != tc.port {
			t.Errorf("%v: got %q %q %v", tc.args, role, port, err)
		}
	}
}
