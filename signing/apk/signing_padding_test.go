package apk_test

import (
	"bytes"
	"testing"

	"github.com/Helix2010/RN-Server/signing/apk"
	"github.com/Helix2010/RN-Server/signing/apk/apktest"
)

// apksigner 在签名块前补零，让块落在 4096 字节边界上（真实 apksigner 35.0.0 的输出）。
// 这种填充只在签名块之前、全是零、不足一页时算作签名块的一部分；其它形态仍是未覆盖字节。
func TestSigningBlockPagePadding(t *testing.T) {
	good := build(t, apktest.Default())
	l := layoutOf(t, good)
	block := apktest.SigningBlock()
	pad := (4096 - l.cdOffset%4096) % 4096
	if pad == 0 {
		pad = 4096 - len(block)%4096
	}
	pageAligned := func(fill byte) []byte {
		// 让"填充 + 块"之后块的起点正好是 4096 的倍数
		n := (4096 - l.cdOffset%4096) % 4096
		if n == 0 {
			n = 4096
		}
		return append(bytes.Repeat([]byte{fill}, n), block...)
	}
	// 块本身长度不是页大小的整数倍时，块起点 = cdOffset + n，是 4096 的倍数
	pkg, err := parse(insertBeforeCD(good, l, pageAligned(0)))
	if l.cdOffset%4096 != 0 {
		if err != nil || !pkg.SigningBlock {
			t.Fatalf("zero page padding before the signing block: %v", err)
		}
	}
	_, err = parse(insertBeforeCD(good, l, pageAligned(1)))
	wantCode(t, err, apk.CodeZipUnaccountedBytes)
	_, err = parse(insertBeforeCD(good, l, append(make([]byte, 3), block...)))
	if l.cdOffset%4096 != 4093 {
		wantCode(t, err, apk.CodeZipUnaccountedBytes)
	}
	_, err = parse(insertBeforeCD(good, l, append(make([]byte, 4096+pad), block...)))
	wantCode(t, err, apk.CodeZipUnaccountedBytes)
}
