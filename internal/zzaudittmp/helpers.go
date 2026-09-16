package main

import (
	"archive/tar"
	"io"
	"sort"
	"time"
)

func newTar(w io.Writer) *tar.Writer { return tar.NewWriter(w) }
func sortStrings(s []string)         { sort.Strings(s) }
func tarHeader(name string, size int64) *tar.Header {
	return &tar.Header{Name: name, Mode: 0o600, Size: size, Typeflag: tar.TypeReg,
		Format: tar.FormatPAX, ModTime: time.Unix(0, 0).UTC()}
}
