// Package apktest 在测试里现场合成 APK。CI 上没有 Android SDK、也不放真实安装包，
// 策略与签名闸的测试都用它造一个与 anyfun 正式包结构相同、可以逐项改坏的包。
//
// 只给测试用，生产代码不得引用。
package apktest

import (
	"bytes"
	"compress/flate"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Helix2010/RN-Server/signing/apk/axml"
	"github.com/Helix2010/RN-Server/signing/trustroots"
)

// Spec 描述要合成的包。
type Spec struct {
	Package     string
	VersionCode int64
	VersionName string
	MinSDK      int64
	TargetSDK   int64

	AllowBackup          *bool // nil = 不写这个属性
	UsesCleartextTraffic *bool

	Debuggable            bool // true = 写上这个属性
	TestOnly              bool
	NetworkSecurityConfig bool
	SharedUserID          bool
	VersionCodeMajor      bool

	Permissions    []string
	PermissionDefs []PermissionDef

	OTACertificatePEM string // meta-data expo.modules.updates.CODE_SIGNING_CERTIFICATE（空 = 不写）
	UpdatesURL        string // meta-data expo.modules.updates.EXPO_UPDATE_URL（空 = 不写）
	UpdatesEnabled    *bool  // meta-data expo.modules.updates.ENABLED

	AppLinksHosts []string // 一个 autoVerify 的 https intent-filter
	CustomSchemes []string // 另一个 intent-filter

	AppConfig    map[string]any // assets/app.config；AppConfigRaw 优先；都为 nil 不写
	AppConfigRaw []byte

	NativeFingerprint string // assets/fingerprint（空 = 不写）

	ExtraEntries []File
}

// PermissionDef 是一条 <permission> 定义。
type PermissionDef struct {
	Name            string
	ProtectionLevel int64
}

// File 是一个 ZIP 条目。
type File struct {
	Name    string
	Data    []byte
	Deflate bool
}

const (
	defaultAPIBaseURL = "https://api.anyfun.win"
	// 与线上 anyfun 包里的写法一致：混合大小写
	defaultBootstrapSigner = "0x9269Ca361b9F0427ac883e89cD5B5fe113BBAD17"
	// DefaultNativeFingerprint 是 Default() 写进 assets/fingerprint 的值。
	DefaultNativeFingerprint = "3f5a1c0e9b7d2468ace013579bdf2468ace01357"
)

// AnyfunPermissions 是线上 anyfun 1.3.16 声明的全部权限（aapt dump badging），
// 除了按包名生成的那一条。
var AnyfunPermissions = []string{
	"android.permission.CAMERA",
	"android.permission.INTERNET",
	"android.permission.POST_NOTIFICATIONS",
	"android.permission.READ_EXTERNAL_STORAGE",
	"android.permission.REQUEST_INSTALL_PACKAGES",
	"android.permission.USE_BIOMETRIC",
	"android.permission.USE_FINGERPRINT",
	"android.permission.VIBRATE",
	"android.permission.WRITE_EXTERNAL_STORAGE",
	"android.permission.ACCESS_NETWORK_STATE",
	"android.permission.ACCESS_WIFI_STATE",
	"android.permission.RECEIVE_BOOT_COMPLETED",
	"android.permission.READ_MEDIA_IMAGES",
	"android.permission.DETECT_SCREEN_CAPTURE",
	"android.permission.WAKE_LOCK",
	"com.google.android.c2dm.permission.RECEIVE",
	"com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE",
	"com.sec.android.provider.badge.permission.READ",
	"com.sec.android.provider.badge.permission.WRITE",
	"com.htc.launcher.permission.READ_SETTINGS",
	"com.htc.launcher.permission.UPDATE_SHORTCUT",
	"com.sonyericsson.home.permission.BROADCAST_BADGE",
	"com.sonymobile.home.permission.PROVIDER_INSERT_BADGE",
	"com.anddoes.launcher.permission.UPDATE_COUNT",
	"com.majeur.launcher.permission.UPDATE_BADGE",
	"com.huawei.android.launcher.permission.CHANGE_BADGE",
	"com.huawei.android.launcher.permission.READ_SETTINGS",
	"com.huawei.android.launcher.permission.WRITE_SETTINGS",
	"android.permission.READ_APP_BADGE",
	"com.oppo.launcher.permission.READ_SETTINGS",
	"com.oppo.launcher.permission.WRITE_SETTINGS",
	"me.everything.badger.permission.BADGE_COUNT_READ",
	"me.everything.badger.permission.BADGE_COUNT_WRITE",
}

// DynamicReceiverPermission 是 RN 按包名生成的那条权限。
func DynamicReceiverPermission(pkg string) string {
	return pkg + ".DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
}

var (
	certOnce sync.Once
	certPEM  string
	certSHA  string
)

// DefaultOTACertificate 返回进程内生成一次的自签名证书（PEM）与其 DER 的 sha256。
func DefaultOTACertificate() (string, string) {
	certOnce.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "apktest OTA"},
			NotBefore:    time.Unix(1700000000, 0),
			NotAfter:     time.Unix(2500000000, 0),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			panic(err)
		}
		certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		sum := sha256.Sum256(der)
		certSHA = hex.EncodeToString(sum[:])
	})
	return certPEM, certSHA
}

// DefaultRoots 是 Default() 包里的信任根（已规范化）。
func DefaultRoots() trustroots.Roots {
	_, sha := DefaultOTACertificate()
	return trustroots.Roots{
		APIBaseURL:             defaultAPIBaseURL,
		OTACertificateSHA256:   sha,
		BootstrapSignerAddress: strings.ToLower(defaultBootstrapSigner),
		AppLinksHosts:          []string{"api.anyfun.win"},
		Scheme:                 "anyfun",
		DistributionChannel:    "direct",
		ApplicationID:          "dex-mobile",
	}
}

func boolPtr(b bool) *bool { return &b }

// Default 返回一个与 anyfun 1.3.16 正式包结构相同、能通过全部策略检查的包描述。
func Default() Spec {
	pem, _ := DefaultOTACertificate()
	const pkg = "com.anyfun.foundation"
	perms := append([]string{}, AnyfunPermissions...)
	perms = append(perms, DynamicReceiverPermission(pkg))
	updatesURL := defaultAPIBaseURL + trustroots.OTAManifestPath
	return Spec{
		Package:           pkg,
		VersionCode:       46,
		VersionName:       "1.3.16",
		MinSDK:            24,
		TargetSDK:         36,
		AllowBackup:       boolPtr(false),
		Permissions:       perms,
		PermissionDefs:    []PermissionDef{{Name: DynamicReceiverPermission(pkg), ProtectionLevel: 2}},
		OTACertificatePEM: pem,
		UpdatesURL:        updatesURL,
		UpdatesEnabled:    boolPtr(true),
		AppLinksHosts:     []string{"api.anyfun.win"},
		CustomSchemes:     []string{"anyfun", "exp+anyfun-app"},
		AppConfig: map[string]any{
			"name":    "AnyFun",
			"slug":    "anyfun-app",
			"version": "1.3.16",
			"scheme":  "anyfun",
			"android": map[string]any{"package": pkg, "versionCode": 46, "allowBackup": false},
			"updates": map[string]any{"enabled": true, "url": updatesURL},
			"extra": map[string]any{
				"apiBaseUrl":             defaultAPIBaseURL,
				"distributionChannel":    "direct",
				"otaChannel":             "production",
				"applicationId":          "dex-mobile",
				"bootstrapSignerAddress": defaultBootstrapSigner,
			},
			"runtimeVersion": "1.3.16",
		},
		NativeFingerprint: DefaultNativeFingerprint,
	}
}

func android(name string, v axml.Value) axml.Attr { return axml.AndroidAttr(name, v) }

// sortAttrs 把带资源 ID 的属性按 ID 升序放前面，没有 ID 的放后面（aapt2 的写法）。
func sortAttrs(attrs []axml.Attr) []axml.Attr {
	sort.SliceStable(attrs, func(i, j int) bool {
		a, b := attrs[i].ResourceID, attrs[j].ResourceID
		switch {
		case a == 0:
			return false
		case b == 0:
			return true
		default:
			return a < b
		}
	})
	return attrs
}

func node(name string, attrs []axml.Attr, children ...*axml.Node) *axml.Node {
	return &axml.Node{Name: name, Attrs: sortAttrs(attrs), Children: children}
}

func named(element, name string, extra ...axml.Attr) *axml.Node {
	return node(element, append([]axml.Attr{android("name", axml.StringValue(name))}, extra...))
}

// ManifestNode 返回 Build 用的清单元素树，测试可以改完再编码。
func ManifestNode(s Spec) *axml.Node {
	manifestAttrs := []axml.Attr{
		android("versionCode", axml.IntValue(s.VersionCode)),
		android("versionName", axml.StringValue(s.VersionName)),
		android("compileSdkVersion", axml.IntValue(36)),
		axml.StringAttr("", "package", 0, s.Package),
		axml.IntAttr("", "platformBuildVersionCode", 0, 36),
	}
	if s.SharedUserID {
		manifestAttrs = append(manifestAttrs, android("sharedUserId", axml.StringValue(s.Package+".shared")))
	}
	if s.VersionCodeMajor {
		manifestAttrs = append(manifestAttrs, android("versionCodeMajor", axml.IntValue(1)))
	}
	root := node("manifest", manifestAttrs)
	root.Children = append(root.Children, node("uses-sdk", []axml.Attr{
		android("minSdkVersion", axml.IntValue(s.MinSDK)),
		android("targetSdkVersion", axml.IntValue(s.TargetSDK)),
	}))
	for _, p := range s.Permissions {
		root.Children = append(root.Children, named("uses-permission", p))
	}
	for _, p := range s.PermissionDefs {
		root.Children = append(root.Children, named("permission", p.Name,
			axml.Attr{Namespace: axml.AndroidNS, Name: "protectionLevel", ResourceID: axml.AttrProtectionLevel, Value: axml.Value{Type: axml.TypeIntHex, Data: uint32(p.ProtectionLevel)}}))
	}
	root.Children = append(root.Children, node("queries", nil,
		node("intent", nil,
			named("action", "android.intent.action.VIEW"),
			node("data", []axml.Attr{android("scheme", axml.StringValue("https"))}))))

	appAttrs := []axml.Attr{
		android("name", axml.StringValue(s.Package+".MainApplication")),
		android("label", axml.Value{Type: axml.TypeReference, Data: 0x7f11001f}),
		android("supportsRtl", axml.BoolValue(true)),
	}
	if s.AllowBackup != nil {
		appAttrs = append(appAttrs, android("allowBackup", axml.BoolValue(*s.AllowBackup)))
	}
	if s.UsesCleartextTraffic != nil {
		appAttrs = append(appAttrs, android("usesCleartextTraffic", axml.BoolValue(*s.UsesCleartextTraffic)))
	}
	if s.Debuggable {
		appAttrs = append(appAttrs, android("debuggable", axml.BoolValue(true)))
	}
	if s.TestOnly {
		appAttrs = append(appAttrs, android("testOnly", axml.BoolValue(true)))
	}
	if s.NetworkSecurityConfig {
		appAttrs = append(appAttrs, android("networkSecurityConfig", axml.Value{Type: axml.TypeReference, Data: 0x7f150001}))
	}
	app := node("application", appAttrs)
	metaString := func(name, value string) *axml.Node {
		return named("meta-data", name, android("value", axml.StringValue(value)))
	}
	if s.OTACertificatePEM != "" {
		app.Children = append(app.Children,
			metaString("expo.modules.updates.CODE_SIGNING_CERTIFICATE", s.OTACertificatePEM),
			metaString("expo.modules.updates.CODE_SIGNING_METADATA", `{"alg":"rsa-v1_5-sha256","keyid":"main"}`))
	}
	if s.UpdatesEnabled != nil {
		app.Children = append(app.Children, named("meta-data", "expo.modules.updates.ENABLED", android("value", axml.BoolValue(*s.UpdatesEnabled))))
	}
	if s.UpdatesURL != "" {
		app.Children = append(app.Children, metaString("expo.modules.updates.EXPO_UPDATE_URL", s.UpdatesURL))
	}

	activity := named("activity", s.Package+".MainActivity", android("exported", axml.BoolValue(true)))
	activity.Children = append(activity.Children, node("intent-filter", nil,
		named("action", "android.intent.action.MAIN"),
		named("category", "android.intent.category.LAUNCHER")))
	if len(s.CustomSchemes) > 0 {
		f := node("intent-filter", nil,
			named("action", "android.intent.action.VIEW"),
			named("category", "android.intent.category.DEFAULT"),
			named("category", "android.intent.category.BROWSABLE"))
		for _, scheme := range s.CustomSchemes {
			f.Children = append(f.Children, node("data", []axml.Attr{android("scheme", axml.StringValue(scheme))}))
		}
		activity.Children = append(activity.Children, f)
	}
	if len(s.AppLinksHosts) > 0 {
		f := node("intent-filter", []axml.Attr{android("autoVerify", axml.BoolValue(true))},
			named("action", "android.intent.action.VIEW"))
		for _, host := range s.AppLinksHosts {
			f.Children = append(f.Children, node("data", []axml.Attr{
				android("scheme", axml.StringValue("https")),
				android("host", axml.StringValue(host)),
				android("pathPrefix", axml.StringValue("/app/wc")),
			}))
		}
		f.Children = append(f.Children,
			named("category", "android.intent.category.BROWSABLE"),
			named("category", "android.intent.category.DEFAULT"))
		activity.Children = append(activity.Children, f)
	}
	app.Children = append(app.Children, activity,
		named("provider", "expo.modules.filesystem.FileSystemFileProvider", android("exported", axml.BoolValue(false))))
	root.Children = append(root.Children, app)
	return root
}

// Build 合成完整的未签名、已对齐的 APK。
func Build(s Spec) ([]byte, error) {
	manifest, err := axml.Encode(ManifestNode(s))
	if err != nil {
		return nil, err
	}
	return BuildWithManifest(s, manifest)
}

// Files 返回 BuildWithManifest 写进 ZIP 的条目，测试可以改完再调用 WriteZip。
func Files(s Spec, manifest []byte) ([]File, error) {
	files := []File{
		{Name: "AndroidManifest.xml", Data: manifest, Deflate: true},
		{Name: "classes.dex", Data: bytes.Repeat([]byte("dex\n035\x00"), 64), Deflate: true},
		{Name: "lib/arm64-v8a/libx.so", Data: bytes.Repeat([]byte{0x7f, 'E', 'L', 'F'}, 32)},
		{Name: "resources.arsc", Data: bytes.Repeat([]byte{0x02, 0x00, 0x0c, 0x00}, 32)},
	}
	switch {
	case s.AppConfigRaw != nil:
		files = append(files, File{Name: "assets/app.config", Data: s.AppConfigRaw, Deflate: true})
	case s.AppConfig != nil:
		raw, err := json.Marshal(s.AppConfig)
		if err != nil {
			return nil, err
		}
		files = append(files, File{Name: "assets/app.config", Data: raw, Deflate: true})
	}
	if s.NativeFingerprint != "" {
		files = append(files, File{Name: "assets/fingerprint", Data: []byte(s.NativeFingerprint), Deflate: true})
	}
	files = append(files, File{Name: "META-INF/com/android/build/gradle/app-metadata.properties", Data: []byte("appMetadataVersion=1.1\n"), Deflate: true})
	files = append(files, s.ExtraEntries...)
	return files, nil
}

// BuildWithManifest 用给定的清单字节合成 APK（清单可以是故意改坏的）。
func BuildWithManifest(s Spec, manifest []byte) ([]byte, error) {
	files, err := Files(s, manifest)
	if err != nil {
		return nil, err
	}
	return WriteZip(files, ZipOptions{Align: true})
}

// ZipOptions 控制 WriteZip 的布局。
type ZipOptions struct {
	Align         bool   // 按 zipalign -P 16 4 对齐 STORED 条目
	SigningBlock  bool   // 在中央目录前插入一个格式正确的 APK Signing Block
	Misalign      string // 故意让这个条目不对齐
	DuplicateName string // 把这个条目写两遍
}

const alignmentExtraID = 0xd935

// WriteZip 写一个 ZIP：本地头不带数据描述符，对齐用 zipalign 的 0xd935 扩展字段。
func WriteZip(files []File, opts ZipOptions) ([]byte, error) {
	var out bytes.Buffer
	var cd bytes.Buffer
	count := 0
	write := func(f File) error {
		if len(f.Name) == 0 || len(f.Name) > 0xffff {
			return errors.New("apktest: bad entry name")
		}
		data := f.Data
		method := uint16(0)
		if f.Deflate {
			var buf bytes.Buffer
			w, err := flate.NewWriter(&buf, flate.BestCompression)
			if err != nil {
				return err
			}
			if _, err := w.Write(f.Data); err != nil {
				return err
			}
			if err := w.Close(); err != nil {
				return err
			}
			data = buf.Bytes()
			method = 8
		}
		crc := crc32.ChecksumIEEE(f.Data)
		offset := out.Len()
		var extra []byte
		if !f.Deflate && (opts.Align || opts.Misalign == f.Name) {
			align := 4
			if strings.HasSuffix(f.Name, ".so") {
				align = 16384
			}
			base := offset + 30 + len(f.Name) + 6
			pad := (align - base%align) % align
			if opts.Misalign == f.Name {
				pad = (pad + 1) % align
				if (base+pad)%align == 0 {
					pad++
				}
			}
			extra = make([]byte, 6+pad)
			binary.LittleEndian.PutUint16(extra, alignmentExtraID)
			binary.LittleEndian.PutUint16(extra[2:], uint16(2+pad))
			binary.LittleEndian.PutUint16(extra[4:], uint16(align))
		}
		if len(data) > 0xfffffffe || len(f.Data) > 0xfffffffe {
			return errors.New("apktest: entry too large")
		}
		lh := make([]byte, 30)
		binary.LittleEndian.PutUint32(lh, 0x04034b50)
		binary.LittleEndian.PutUint16(lh[4:], 20)
		binary.LittleEndian.PutUint16(lh[8:], method)
		binary.LittleEndian.PutUint16(lh[10:], 0x0821) // 1981-01-01 01:01（与 AGP 一致）
		binary.LittleEndian.PutUint16(lh[12:], 0x0221)
		binary.LittleEndian.PutUint32(lh[14:], crc)
		binary.LittleEndian.PutUint32(lh[18:], uint32(len(data)))
		binary.LittleEndian.PutUint32(lh[22:], uint32(len(f.Data)))
		binary.LittleEndian.PutUint16(lh[26:], uint16(len(f.Name)))
		binary.LittleEndian.PutUint16(lh[28:], uint16(len(extra)))
		out.Write(lh)
		out.WriteString(f.Name)
		out.Write(extra)
		out.Write(data)

		rec := make([]byte, 46)
		binary.LittleEndian.PutUint32(rec, 0x02014b50)
		binary.LittleEndian.PutUint16(rec[4:], 20)
		binary.LittleEndian.PutUint16(rec[6:], 20)
		binary.LittleEndian.PutUint16(rec[10:], method)
		binary.LittleEndian.PutUint16(rec[12:], 0x0821)
		binary.LittleEndian.PutUint16(rec[14:], 0x0221)
		binary.LittleEndian.PutUint32(rec[16:], crc)
		binary.LittleEndian.PutUint32(rec[20:], uint32(len(data)))
		binary.LittleEndian.PutUint32(rec[24:], uint32(len(f.Data)))
		binary.LittleEndian.PutUint16(rec[28:], uint16(len(f.Name)))
		binary.LittleEndian.PutUint32(rec[42:], uint32(offset))
		cd.Write(rec)
		cd.WriteString(f.Name)
		count++
		return nil
	}
	for _, f := range files {
		if err := write(f); err != nil {
			return nil, err
		}
		if f.Name == opts.DuplicateName {
			if err := write(f); err != nil {
				return nil, err
			}
		}
	}
	if opts.SigningBlock {
		out.Write(SigningBlock())
	}
	if count > 0xfffe {
		return nil, errors.New("apktest: too many entries")
	}
	cdOffset := out.Len()
	out.Write(cd.Bytes())
	eocd := make([]byte, 22)
	binary.LittleEndian.PutUint32(eocd, 0x06054b50)
	binary.LittleEndian.PutUint16(eocd[8:], uint16(count))
	binary.LittleEndian.PutUint16(eocd[10:], uint16(count))
	binary.LittleEndian.PutUint32(eocd[12:], uint32(cd.Len()))
	binary.LittleEndian.PutUint32(eocd[16:], uint32(cdOffset))
	out.Write(eocd)
	return out.Bytes(), nil
}

// SigningBlock 返回一个格式正确（但不含有效签名）的 APK Signing Block。
func SigningBlock() []byte {
	value := make([]byte, 64)
	pair := make([]byte, 12)
	binary.LittleEndian.PutUint64(pair, uint64(4+len(value)))
	binary.LittleEndian.PutUint32(pair[8:], 0x7109871a) // v2 签名块的 ID
	pairs := append(pair, value...)
	size := uint64(len(pairs) + 8 + 16)
	block := make([]byte, 8)
	binary.LittleEndian.PutUint64(block, size)
	block = append(block, pairs...)
	block = binary.LittleEndian.AppendUint64(block, size)
	return append(block, "APK Sig Block 42"...)
}

// StripSigningBlock 去掉 APK Signing Block 并改好 EOCD 里的中央目录偏移，得到"未签名包"。
// 只处理没有 ZIP 注释的包（APK 都没有）。
func StripSigningBlock(apk []byte) ([]byte, error) {
	if len(apk) < 22 || binary.LittleEndian.Uint32(apk[len(apk)-22:]) != 0x06054b50 {
		return nil, errors.New("apktest: no end-of-central-directory record at the end of the file")
	}
	eocd := len(apk) - 22
	cdOffset := int(binary.LittleEndian.Uint32(apk[eocd+16:]))
	if cdOffset < 24 || cdOffset > eocd {
		return nil, errors.New("apktest: bad central directory offset")
	}
	if string(apk[cdOffset-16:cdOffset]) != "APK Sig Block 42" {
		return nil, errors.New("apktest: no APK Signing Block before the central directory")
	}
	size := binary.LittleEndian.Uint64(apk[cdOffset-24:])
	start := cdOffset - int(size) - 8
	if size > uint64(cdOffset) || start < 0 || binary.LittleEndian.Uint64(apk[start:]) != size {
		return nil, fmt.Errorf("apktest: malformed APK Signing Block (size %d)", size)
	}
	out := make([]byte, 0, len(apk)-(cdOffset-start))
	out = append(out, apk[:start]...)
	out = append(out, apk[cdOffset:]...)
	binary.LittleEndian.PutUint32(out[len(out)-22+16:], uint32(start))
	return out, nil
}
