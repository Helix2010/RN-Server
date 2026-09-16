package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
)

type fakeGetter struct {
	body string
	err  error
}

func (f fakeGetter) Get(context.Context, string) (io.ReadCloser, error) {
	if f.err != nil {
		return nil, f.err
	}
	return io.NopCloser(strings.NewReader(f.body)), nil
}

// 上传完必须从桶里取回来重算一次（设计 §12 第 1 级）。
//
// 本地那个 sha256 是封包时边写边算的，它只能证明「我封出来的是这个」。
// 一次截断的上传——多段中途失败但对象被创建，或者代理层截断——会留下一个短
// 对象，而库里记着完整包的 sha256 和 size、状态 succeeded、控制台全绿。
// 发现的时机是灾难当天下载下来对不上，而那时没有第二次机会。
func TestUploadedObjectIsReadBackAndVerified(t *testing.T) {
	full := "the whole package, every byte of it"
	sum := sha256.Sum256([]byte(full))
	want := hex.EncodeToString(sum[:])
	size := int64(len(full))
	ctx := context.Background()

	if err := verifyUploadedObject(ctx, fakeGetter{body: full}, "k", want, size); err != nil {
		t.Fatalf("完整的对象不该报错: %v", err)
	}

	t.Run("截断的上传", func(t *testing.T) {
		err := verifyUploadedObject(ctx, fakeGetter{body: full[:10]}, "k", want, size)
		if err == nil {
			t.Fatal("桶里只有 10 字节，却当成上传成功了")
		}
		if !strings.Contains(err.Error(), "truncated") {
			t.Errorf("错误信息没说清是截断: %v", err)
		}
	})

	t.Run("内容被换掉但长度一样", func(t *testing.T) {
		other := strings.Repeat("x", len(full))
		if err := verifyUploadedObject(ctx, fakeGetter{body: other}, "k", want, size); err == nil {
			t.Fatal("长度一样但内容不同，居然通过了——只比长度是不够的")
		}
	})

	t.Run("取不回来", func(t *testing.T) {
		if err := verifyUploadedObject(ctx, fakeGetter{err: errors.New("no such key")},
			"k", want, size); err == nil {
			t.Fatal("对象根本取不回来，却当成上传成功了")
		}
	})
}
