package policy

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

//go:embed permissions.json
var permissionsJSON []byte

type permissionList struct {
	Comment       string              `json:"comment"`
	Format        string              `json:"format"`
	Allowed       []string            `json:"allowed"`
	ByChannel     map[string][]string `json:"byChannel"`
	PackageScoped []string            `json:"packageScoped"`
	Definitions   []string            `json:"definitions"`
}

const permissionsFormat = "rn-signer-permissions/v1"

var permissions = mustLoadPermissions(permissionsJSON)

func mustLoadPermissions(raw []byte) permissionList {
	list, err := loadPermissions(raw)
	if err != nil {
		panic("policy: embedded permissions.json is invalid: " + err.Error())
	}
	return list
}

func loadPermissions(raw []byte) (permissionList, error) {
	var list permissionList
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&list); err != nil {
		return list, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return list, errors.New("trailing data")
	}
	if list.Format != permissionsFormat || len(list.Allowed) == 0 {
		return list, errors.New("format or allowed list is wrong")
	}
	seen := map[string]bool{}
	check := func(names []string, scoped bool) error {
		for _, name := range names {
			if seen[name] && !scoped {
				return fmt.Errorf("duplicate permission %s", name)
			}
			seen[name] = true
			if scoped && !strings.HasPrefix(name, "{package}.") {
				return fmt.Errorf("package-scoped permission %s must start with {package}.", name)
			}
			if strings.TrimSpace(name) != name || name == "" {
				return fmt.Errorf("permission %q has whitespace", name)
			}
		}
		return nil
	}
	if err := check(list.Allowed, false); err != nil {
		return list, err
	}
	for _, names := range list.ByChannel {
		if err := check(names, false); err != nil {
			return list, err
		}
	}
	if err := check(list.PackageScoped, true); err != nil {
		return list, err
	}
	if err := check(list.Definitions, true); err != nil {
		return list, err
	}
	return list, nil
}

// AllowedPermissions 返回某个包名、某个渠道允许声明的全部 uses-permission，排序后返回。
func AllowedPermissions(packageName, channel string) []string {
	set := allowedPermissionSet(permissions, packageName, channel)
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func allowedPermissionSet(list permissionList, packageName, channel string) map[string]bool {
	set := map[string]bool{}
	for _, name := range list.Allowed {
		set[name] = true
	}
	for _, name := range list.ByChannel[channel] {
		set[name] = true
	}
	for _, name := range list.PackageScoped {
		set[strings.Replace(name, "{package}", packageName, 1)] = true
	}
	return set
}

func allowedDefinitionSet(list permissionList, packageName string) map[string]bool {
	set := map[string]bool{}
	for _, name := range list.Definitions {
		set[strings.Replace(name, "{package}", packageName, 1)] = true
	}
	return set
}
