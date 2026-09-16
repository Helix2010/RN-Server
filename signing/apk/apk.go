// Package apk 解析不可信的未签名 APK，给签名闸的策略提供事实。
//
// 它运行在检查进程里（无网络、无密钥、独立用户），输入是构建机交付的文件，按恶意
// 输入处理：所有长度、偏移、计数先做上限与越界检查；只解压策略需要的四个条目，
// 每个都有解压上限并校验 CRC；ZIP 结构上凡是不同解析器可能读出不同内容的构造
// （重复条目、中央目录与本地头不一致、条目重叠、未被任何条目覆盖的字节、zip64、
// 注释）一律拒绝。解析器只报事实与结构错误，签不签由 policy 决定。
package apk

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Helix2010/RN-Server/signing/apk/axml"
)

// Limits 限制解析一个不可信 APK 的资源消耗。
type Limits struct {
	MaxFileSize             int64 // 整个文件
	MaxEntries              int   // 条目数
	MaxNameLength           int   // 条目名字节数
	MaxCentralDirectorySize int64 // 中央目录字节数
	MaxManifestSize         int64 // AndroidManifest.xml 解压后
	MaxJSONAssetSize        int64 // assets/app.config、assets/app.manifest 解压后
	MaxFingerprintSize      int64 // assets/fingerprint 解压后
}

// DefaultLimits 远大于真实包（anyfun 1.3.16：40 MiB、1210 个条目、清单 34 KiB）。
func DefaultLimits() Limits {
	return Limits{
		MaxFileSize:             512 << 20,
		MaxEntries:              20000,
		MaxNameLength:           1024,
		MaxCentralDirectorySize: 32 << 20,
		MaxManifestSize:         8 << 20,
		MaxJSONAssetSize:        8 << 20,
		MaxFingerprintSize:      1024,
	}
}

// Error 是结构性拒绝。Code 稳定，Detail 可以安全打印到终端。
type Error struct {
	Code   string
	Detail string
}

func (e *Error) Error() string { return e.Code + ": " + e.Detail }

func errorf(code, format string, args ...any) *Error {
	return &Error{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// 错误码。axml 的错误码（AXML_*）原样透传。
const (
	CodeReadFailed             = "APK_READ_FAILED"
	CodeZipTooLarge            = "ZIP_TOO_LARGE"
	CodeZipNoEOCD              = "ZIP_NO_EOCD"
	CodeZipComment             = "ZIP_COMMENT"
	CodeZip64Unsupported       = "ZIP64_UNSUPPORTED"
	CodeZipMultiDisk           = "ZIP_MULTI_DISK"
	CodeZipCDBounds            = "ZIP_CD_BOUNDS"
	CodeZipTooManyEntries      = "ZIP_TOO_MANY_ENTRIES"
	CodeZipCDEntry             = "ZIP_CD_ENTRY"
	CodeZipNameInvalid         = "ZIP_NAME_INVALID"
	CodeZipDuplicateEntry      = "ZIP_DUPLICATE_ENTRY"
	CodeZipEncrypted           = "ZIP_ENCRYPTED"
	CodeZipMethodUnsupported   = "ZIP_METHOD_UNSUPPORTED"
	CodeZipLocalHeaderMismatch = "ZIP_LOCAL_HEADER_MISMATCH"
	CodeZipOverlap             = "ZIP_OVERLAP"
	CodeZipUnaccountedBytes    = "ZIP_UNACCOUNTED_BYTES"
	CodeZipEntryTooLarge       = "ZIP_ENTRY_TOO_LARGE"
	CodeZipEntryCorrupt        = "ZIP_ENTRY_CORRUPT"
	CodeManifestMissing        = "MANIFEST_MISSING"
	CodeManifestStructure      = "MANIFEST_STRUCTURE"
	CodeManifestAttributeType  = "MANIFEST_ATTRIBUTE_TYPE"
	// CodeManifestElementNotAllowed：<manifest> / <application> 下出现允许列表之外的元素，
	// 或任何位置出现 <key-sets> 等改变升级签名要求的元素。
	CodeManifestElementNotAllowed = "MANIFEST_ELEMENT_NOT_ALLOWED"
	CodeEmbeddedConfigInvalid     = "EMBEDDED_CONFIG_INVALID"
	CodeEmbeddedConfigDupKey      = "EMBEDDED_CONFIG_DUPLICATE_KEY"
)

// 需要读的条目。
const (
	ManifestEntry    = "AndroidManifest.xml"
	AppConfigEntry   = "assets/app.config"
	AppManifestEntry = "assets/app.manifest"
	FingerprintEntry = "assets/fingerprint"
)

// Package 是解析结果。
type Package struct {
	Size   int64
	SHA256 string

	Entries []Entry // 中央目录顺序

	SigningBlock     bool     // 中央目录前有 APK Signing Block
	V1SignatureFiles []string // META-INF/ 下的 JAR 签名文件

	Misaligned      []Misaligned // 不满足 zipalign -c -P 16 4 的条目（最多 32 个）
	MisalignedCount int

	Manifest *Manifest

	AppConfig      *ExpoConfig // assets/app.config；没有为 nil
	HasAppManifest bool        // 有 assets/app.manifest
	AppManifest    *ExpoConfig // assets/app.manifest 的 extra.expoClient；没有为 nil

	NativeFingerprint *string // assets/fingerprint 去掉首尾空白；没有为 nil
}

// Entry 是一个 ZIP 条目。
type Entry struct {
	Name              string
	Method            uint16
	Flags             uint16
	CRC32             uint32
	CompressedSize    int64
	UncompressedSize  int64
	LocalHeaderOffset int64
	DataOffset        int64
}

// Misaligned 是一个没有对齐的 STORED 条目。
type Misaligned struct {
	Name       string
	DataOffset int64
	Alignment  int64
}

const maxMisalignedListed = 32

// ParseFile 打开文件、计算 sha256 并解析。
func ParseFile(path string, lim Limits) (*Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errorf(CodeReadFailed, "cannot open the APK: %v", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, errorf(CodeReadFailed, "cannot stat the APK: %v", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errorf(CodeReadFailed, "the APK is not a regular file")
	}
	return Parse(f, info.Size(), lim)
}

// Parse 解析 r 里 size 字节的 APK。
func Parse(r io.ReaderAt, size int64, lim Limits) (*Package, error) {
	if size < 0 || size > lim.MaxFileSize {
		return nil, errorf(CodeZipTooLarge, "APK is %d bytes, over the %d byte limit", size, lim.MaxFileSize)
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.NewSectionReader(r, 0, size))
	if err != nil || n != size {
		return nil, errorf(CodeReadFailed, "cannot read the APK: %v", readErr(err))
	}
	pkg := &Package{Size: size, SHA256: hex.EncodeToString(hash.Sum(nil))}

	z, err := readZip(r, size, lim)
	if err != nil {
		return nil, err
	}
	pkg.Entries = z.entries
	pkg.SigningBlock = z.signingBlock
	pkg.V1SignatureFiles = v1SignatureFiles(z.entries)
	pkg.Misaligned, pkg.MisalignedCount = misaligned(z.entries)

	manifestEntry, ok := z.byName[ManifestEntry]
	if !ok {
		return nil, errorf(CodeManifestMissing, "the APK has no AndroidManifest.xml")
	}
	raw, err := z.read(manifestEntry, lim.MaxManifestSize)
	if err != nil {
		return nil, err
	}
	doc, err := axml.Decode(raw, axmlLimits(lim))
	if err != nil {
		var ae *axml.Error
		if errors.As(err, &ae) {
			return nil, &Error{Code: ae.Code, Detail: "AndroidManifest.xml: " + ae.Detail}
		}
		return nil, errorf(axml.CodeMalformed, "AndroidManifest.xml: %v", err)
	}
	if pkg.Manifest, err = extractManifest(doc); err != nil {
		return nil, err
	}

	if e, ok := z.byName[AppConfigEntry]; ok {
		raw, err := z.read(e, lim.MaxJSONAssetSize)
		if err != nil {
			return nil, err
		}
		obj, err := parseStrictJSONObject(raw, AppConfigEntry)
		if err != nil {
			return nil, err
		}
		pkg.AppConfig = expoConfigFrom(obj)
	}
	if e, ok := z.byName[AppManifestEntry]; ok {
		raw, err := z.read(e, lim.MaxJSONAssetSize)
		if err != nil {
			return nil, err
		}
		obj, err := parseStrictJSONObject(raw, AppManifestEntry)
		if err != nil {
			return nil, err
		}
		pkg.HasAppManifest = true
		if extra, ok := obj["extra"].(map[string]any); ok {
			if client, ok := extra["expoClient"].(map[string]any); ok {
				pkg.AppManifest = expoConfigFrom(client)
			}
		}
	}
	if e, ok := z.byName[FingerprintEntry]; ok {
		raw, err := z.read(e, lim.MaxFingerprintSize)
		if err != nil {
			return nil, err
		}
		value, err := fingerprintValue(raw)
		if err != nil {
			return nil, err
		}
		pkg.NativeFingerprint = &value
	}
	return pkg, nil
}

func axmlLimits(lim Limits) axml.Limits {
	out := axml.DefaultLimits()
	if lim.MaxManifestSize < int64(out.MaxSize) {
		out.MaxSize = int(lim.MaxManifestSize)
	}
	return out
}

func readErr(err error) error {
	if err == nil {
		return io.ErrUnexpectedEOF
	}
	return err
}
