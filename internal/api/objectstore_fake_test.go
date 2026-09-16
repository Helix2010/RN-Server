package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/objectstore"
)

// fakeObjectStore 是测试用对象存储：按 key 保存字节与 ETag，Stat/Get 可被替换成失败。
type fakeObjectStore struct {
	versioningEnabled bool
	versioningErr     error
	putErr            error
	getErr            error
	corsErr           error
	objects           map[string]fakeObject
	statErr           error
	listErr           error
	deleteErr         error
}

type fakeObject struct {
	body        []byte
	etag        string
	contentType string
}

func newFakeObjectStore() *fakeObjectStore { return &fakeObjectStore{objects: map[string]fakeObject{}} }

func (f *fakeObjectStore) put(key string, body []byte, etag string) {
	f.objects[key] = fakeObject{body: body, etag: etag, contentType: "application/octet-stream"}
}

// 和真的客户端一样包着 objectstore.ErrObjectNotFound：备份上传前靠它区分「不存在」和「读不了」
var errFakeObjectMissing = fmt.Errorf("fake object store: no such key: %w", objectstore.ErrObjectNotFound)

func (f *fakeObjectStore) Stat(_ context.Context, key string) (objectstore.ObjectInfo, error) {
	if f.statErr != nil {
		return objectstore.ObjectInfo{}, f.statErr
	}
	object, ok := f.objects[key]
	if !ok {
		return objectstore.ObjectInfo{}, errFakeObjectMissing
	}
	return objectstore.ObjectInfo{Size: int64(len(object.body)), ContentType: object.contentType, ETag: object.etag}, nil
}

func (f *fakeObjectStore) Head(ctx context.Context, key string) (int64, string, error) {
	info, err := f.Stat(ctx, key)
	return info.Size, info.ContentType, err
}

func (f *fakeObjectStore) Get(_ context.Context, key string) (io.ReadCloser, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	object, ok := f.objects[key]
	if !ok {
		return nil, errFakeObjectMissing
	}
	return io.NopCloser(bytes.NewReader(object.body)), nil
}

func (f *fakeObjectStore) GetRange(_ context.Context, key string, start, end int64) (io.ReadCloser, error) {
	object, ok := f.objects[key]
	if !ok || start < 0 || end >= int64(len(object.body)) || start > end {
		return nil, errFakeObjectMissing
	}
	return io.NopCloser(bytes.NewReader(object.body[start : end+1])), nil
}

func (f *fakeObjectStore) Put(_ context.Context, key string, body io.Reader, _ int64, contentType string) error {
	if f.putErr != nil {
		return f.putErr
	}
	raw, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	f.objects[key] = fakeObject{body: raw, etag: "put-" + key, contentType: contentType}
	return nil
}

func (f *fakeObjectStore) Delete(_ context.Context, key string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.objects, key)
	return nil
}

func (f *fakeObjectStore) List(_ context.Context, prefix string) ([]string, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if prefix == "" {
		return nil, errors.New("fake object store: empty prefix")
	}
	keys := []string(nil)
	for key := range f.objects {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

func (f *fakeObjectStore) PresignPut(context.Context, string, string, int64, time.Duration) (string, map[string]string, error) {
	return "", nil, errors.New("not supported by fake")
}
func (f *fakeObjectStore) PresignGet(context.Context, string, time.Duration, string) (string, error) {
	return "", errors.New("not supported by fake")
}
func (f *fakeObjectStore) CreateMultipartUpload(context.Context, string, string) (string, error) {
	return "", errors.New("not supported by fake")
}
func (f *fakeObjectStore) UploadPart(context.Context, string, string, int, io.Reader, int64) (string, error) {
	return "", errors.New("not supported by fake")
}
func (f *fakeObjectStore) PresignUploadPart(context.Context, string, string, int, time.Duration) (string, map[string]string, error) {
	return "", nil, errors.New("not supported by fake")
}
func (f *fakeObjectStore) ListParts(context.Context, string, string) ([]objectstore.CompletedPart, error) {
	return nil, errors.New("not supported by fake")
}
func (f *fakeObjectStore) CompleteMultipartUpload(context.Context, string, string, []objectstore.CompletedPart) error {
	return errors.New("not supported by fake")
}
func (f *fakeObjectStore) AbortMultipartUpload(context.Context, string, string) error {
	return errors.New("not supported by fake")
}
func (f *fakeObjectStore) Test(context.Context) error { return nil }

var _ objectstore.Client = (*fakeObjectStore)(nil)

// versioningEnabled 默认 false：假桶不该让「versioning 开着吗」这个问题
// 默认得到一个乐观的答案。要测开着的路径就显式设成 true
func (f *fakeObjectStore) BucketVersioning(context.Context) (bool, error) {
	return f.versioningEnabled, f.versioningErr
}
