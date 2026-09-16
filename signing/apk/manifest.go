package apk

import (
	"github.com/Helix2010/RN-Server/signing/apk/axml"
)

// Manifest 是清单里策略关心的事实，全部按 Android 的读法（框架属性按资源 ID）取出。
type Manifest struct {
	Package          string  // <manifest package>：无命名空间、无资源 ID 的字符串字面量
	VersionCode      *int64  // android:versionCode 整数字面量；没有为 nil
	VersionCodeMajor bool    // 出现了 android:versionCodeMajor（任何类型）
	VersionName      *string // android:versionName 字符串字面量；没有为 nil
	SharedUserID     bool    // 出现了 android:sharedUserId
	MinSDK           *int64  // <uses-sdk android:minSdkVersion>；没有为 nil
	TargetSDK        *int64  // <uses-sdk android:targetSdkVersion>；没有为 nil

	Application *Application // 没有 <application> 为 nil

	UsesPermissions  []UsesPermission // <manifest> 的直接子元素 uses-permission、uses-permission-sdk-23、uses-permission-sdk-m
	Permissions      []PermissionDef  // <manifest> 的直接子元素 <permission>
	PermissionTrees  int
	PermissionGroups int

	IntentFilters []IntentFilter // application 下 activity、activity-alias、service、receiver、provider 的 intent-filter
}

// Application 是 <application> 的事实。
type Application struct {
	Debuggable            bool // 出现了 android:debuggable（任何值）
	TestOnly              bool // 出现了 android:testOnly（任何值）
	NetworkSecurityConfig bool // 出现了 android:networkSecurityConfig
	AllowBackup           *bool
	UsesCleartextTraffic  *bool
	MetaData              []MetaData // <application> 的直接子元素 <meta-data>，名字不重复
}

// UsesPermission 是一条权限声明。
type UsesPermission struct {
	Element string // uses-permission / uses-permission-sdk-23 / uses-permission-sdk-m
	Name    string
	MaxSDK  *int64
}

// PermissionDef 是一条 <permission> 定义。
type PermissionDef struct {
	Name            string
	ProtectionLevel *int64
}

// MetaData 是 <application> 下的一条 <meta-data>。Value.Type 为 0 表示没有 android:value。
type MetaData struct {
	Name        string
	Value       axml.Value
	HasResource bool
}

// IntentFilter 是一个组件上的 intent-filter。
type IntentFilter struct {
	Component     string // activity / activity-alias / service / receiver / provider
	ComponentName string
	AutoVerify    *bool
	Actions       []string
	Categories    []string
	Schemes       []string
	Hosts         []string
}

var componentElements = map[string]bool{
	"activity": true, "activity-alias": true, "service": true, "receiver": true, "provider": true,
}

var usesPermissionElements = map[string]bool{
	"uses-permission": true, "uses-permission-sdk-23": true, "uses-permission-sdk-m": true,
}

// topLevelOnly 是只允许作为 <manifest> 直接子元素出现的元素。放在别处 Android 会忽略，
// 而我们也许会看见——干脆不允许。
var topLevelOnly = map[string]bool{
	"uses-permission": true, "uses-permission-sdk-23": true, "uses-permission-sdk-m": true,
	"permission": true, "permission-tree": true, "permission-group": true,
	"uses-sdk": true, "application": true,
}

func structuref(format string, args ...any) *Error {
	return errorf(CodeManifestStructure, format, args...)
}

func typef(format string, args ...any) *Error {
	return errorf(CodeManifestAttributeType, format, args...)
}

func attrName(id uint32) string {
	name, _ := axml.FrameworkAttrName(id)
	return "android:" + name
}

func stringAttr(el *axml.Element, id uint32) (*string, error) {
	a, ok := el.Attr(id)
	if !ok {
		return nil, nil
	}
	s, ok := a.Value.Str()
	if !ok {
		return nil, typef("<%s %s> must be a string literal (type 0x%02x)", el.Name, attrName(id), a.Value.Type)
	}
	return &s, nil
}

func intAttr(el *axml.Element, id uint32) (*int64, error) {
	a, ok := el.Attr(id)
	if !ok {
		return nil, nil
	}
	n, ok := a.Value.Int()
	if !ok {
		return nil, typef("<%s %s> must be an integer literal (type 0x%02x)", el.Name, attrName(id), a.Value.Type)
	}
	return &n, nil
}

func boolAttr(el *axml.Element, id uint32) (*bool, error) {
	a, ok := el.Attr(id)
	if !ok {
		return nil, nil
	}
	b, ok := a.Value.Bool()
	if !ok {
		return nil, typef("<%s %s> must be a boolean literal (type 0x%02x)", el.Name, attrName(id), a.Value.Type)
	}
	return &b, nil
}

func requiredName(el *axml.Element) (string, error) {
	name, err := stringAttr(el, axml.AttrName)
	if err != nil {
		return "", err
	}
	if name == nil || *name == "" {
		return "", structuref("<%s> has no android:name", el.Name)
	}
	return *name, nil
}

func present(el *axml.Element, id uint32) bool {
	_, ok := el.Attr(id)
	return ok
}

func extractManifest(doc *axml.Document) (*Manifest, error) {
	root := doc.Root
	if root.Name != "manifest" {
		return nil, structuref("root element is <%s>, not <manifest>", axml.Quote(root.Name))
	}
	if err := checkPlacement(root, 0); err != nil {
		return nil, err
	}
	m := &Manifest{}
	pkg, ok := root.AttrByName("", "package")
	if !ok {
		return nil, structuref("<manifest> has no package attribute")
	}
	if pkg.ResourceID != 0 {
		return nil, structuref("<manifest package> must not carry a resource id")
	}
	s, ok := pkg.Value.Str()
	if !ok {
		return nil, typef("<manifest package> must be a string literal (type 0x%02x)", pkg.Value.Type)
	}
	m.Package = s

	var err error
	if m.VersionCode, err = intAttr(root, axml.AttrVersionCode); err != nil {
		return nil, err
	}
	if m.VersionName, err = stringAttr(root, axml.AttrVersionName); err != nil {
		return nil, err
	}
	m.VersionCodeMajor = present(root, axml.AttrVersionCodeMajor)
	m.SharedUserID = present(root, axml.AttrSharedUserID)

	usesSDK := 0
	applications := 0
	for _, child := range root.Children {
		switch {
		case child.Name == "uses-sdk":
			usesSDK++
			if usesSDK > 1 {
				return nil, structuref("<manifest> has more than one <uses-sdk>")
			}
			if m.MinSDK, err = intAttr(child, axml.AttrMinSDKVersion); err != nil {
				return nil, err
			}
			if m.TargetSDK, err = intAttr(child, axml.AttrTargetSDKVersion); err != nil {
				return nil, err
			}
			if _, err = intAttr(child, axml.AttrMaxSDKVersion); err != nil {
				return nil, err
			}
		case usesPermissionElements[child.Name]:
			name, err := requiredName(child)
			if err != nil {
				return nil, err
			}
			maxSDK, err := intAttr(child, axml.AttrMaxSDKVersion)
			if err != nil {
				return nil, err
			}
			m.UsesPermissions = append(m.UsesPermissions, UsesPermission{Element: child.Name, Name: name, MaxSDK: maxSDK})
		case child.Name == "permission":
			name, err := requiredName(child)
			if err != nil {
				return nil, err
			}
			level, err := intAttr(child, axml.AttrProtectionLevel)
			if err != nil {
				return nil, err
			}
			m.Permissions = append(m.Permissions, PermissionDef{Name: name, ProtectionLevel: level})
		case child.Name == "permission-tree":
			m.PermissionTrees++
		case child.Name == "permission-group":
			m.PermissionGroups++
		case child.Name == "application":
			applications++
			if applications > 1 {
				return nil, structuref("<manifest> has more than one <application>")
			}
			app, filters, err := extractApplication(child)
			if err != nil {
				return nil, err
			}
			m.Application = app
			m.IntentFilters = filters
		}
	}
	return m, nil
}

// checkPlacement 保证只该出现在顶层的元素没有藏在别处。
func checkPlacement(el *axml.Element, depth int) error {
	for _, child := range el.Children {
		if depth > 0 && topLevelOnly[child.Name] {
			return structuref("<%s> must be a direct child of <manifest>, found inside <%s>", child.Name, axml.Quote(el.Name))
		}
		if err := checkPlacement(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func extractApplication(el *axml.Element) (*Application, []IntentFilter, error) {
	app := &Application{
		Debuggable:            present(el, axml.AttrDebuggable),
		TestOnly:              present(el, axml.AttrTestOnly),
		NetworkSecurityConfig: present(el, axml.AttrNetworkSecurityConfig),
	}
	var err error
	if app.AllowBackup, err = boolAttr(el, axml.AttrAllowBackup); err != nil {
		return nil, nil, err
	}
	if app.UsesCleartextTraffic, err = boolAttr(el, axml.AttrUsesCleartextTraffic); err != nil {
		return nil, nil, err
	}
	var filters []IntentFilter
	metaNames := map[string]bool{}
	for _, child := range el.Children {
		switch {
		case child.Name == "meta-data":
			name, err := requiredName(child)
			if err != nil {
				return nil, nil, err
			}
			// Android 把 meta-data 放进 Bundle，同名的后一条覆盖前一条；策略按名字取值时
			// 可能取到另一条。同名直接拒绝
			if metaNames[name] {
				return nil, nil, structuref("<application> has more than one <meta-data> named %s", axml.Quote(name))
			}
			metaNames[name] = true
			md := MetaData{Name: name, HasResource: present(child, axml.AttrResource)}
			if a, ok := child.Attr(axml.AttrValue); ok {
				md.Value = a.Value
			}
			app.MetaData = append(app.MetaData, md)
		case componentElements[child.Name]:
			componentName, err := requiredName(child)
			if err != nil {
				return nil, nil, err
			}
			for _, f := range child.Children {
				if f.Name != "intent-filter" {
					continue
				}
				filter, err := extractIntentFilter(child.Name, componentName, f)
				if err != nil {
					return nil, nil, err
				}
				filters = append(filters, filter)
			}
		}
	}
	return app, filters, nil
}

func extractIntentFilter(component, componentName string, el *axml.Element) (IntentFilter, error) {
	filter := IntentFilter{Component: component, ComponentName: componentName}
	var err error
	if filter.AutoVerify, err = boolAttr(el, axml.AttrAutoVerify); err != nil {
		return filter, err
	}
	for _, child := range el.Children {
		switch child.Name {
		case "action":
			name, err := requiredName(child)
			if err != nil {
				return filter, err
			}
			filter.Actions = append(filter.Actions, name)
		case "category":
			name, err := requiredName(child)
			if err != nil {
				return filter, err
			}
			filter.Categories = append(filter.Categories, name)
		case "data":
			scheme, err := stringAttr(child, axml.AttrScheme)
			if err != nil {
				return filter, err
			}
			host, err := stringAttr(child, axml.AttrHost)
			if err != nil {
				return filter, err
			}
			if scheme != nil {
				filter.Schemes = append(filter.Schemes, *scheme)
			}
			if host != nil {
				filter.Hosts = append(filter.Hosts, *host)
			}
		}
	}
	return filter, nil
}
