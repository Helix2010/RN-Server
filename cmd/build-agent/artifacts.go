package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
)

// 执行进程交回的产物对控制进程是**不可信数据**：只读字节、算 sha256、上传。不执行、不解析
// 任何可执行内容，大小有上限，拒绝符号链接、硬链接与特殊文件。
//
// 读的时候就复制进控制进程自己的状态目录（spool），之后算哈希、上传、签出处都用这份副本：
// 执行进程的文件属于 builder，它残留的进程可以在控制进程读完之后改写同一个 inode，
// 拿同一个路径再读一次就可能是另一份字节。

const spoolDirName = "spool"

// spooledFile 是控制进程自己的一份产物副本。
type spooledFile struct {
	Path   string
	SHA256 string
	Size   int64
}

func (a *agent) spoolDir(jobID string) string {
	return filepath.Join(a.cfg.StateDir, spoolDirName, jobID)
}

// spoolOutput 从 out/ 取一个产物复制进 spool，边复制边算 sha256。
func spoolOutput(layout jobspec.Layout, name, spoolDir string, limit int64) (spooledFile, error) {
	src := layout.OutFile(name)
	// O_NOFOLLOW：最后一段是符号链接就打不开；O_NONBLOCK：FIFO 不会把控制进程卡住
	in, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return spooledFile{}, fmt.Errorf("the build runner did not hand over %s: %w", name, err)
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return spooledFile{}, err
	}
	if !info.Mode().IsRegular() {
		return spooledFile{}, fmt.Errorf("%s from the build runner is not a regular file", name)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Nlink != 1 {
		return spooledFile{}, fmt.Errorf("%s from the build runner is a hard link; refusing it", name)
	}
	if info.Size() > limit {
		return spooledFile{}, fmt.Errorf("%s from the build runner is %d bytes, over the %d byte limit", name, info.Size(), limit)
	}
	if info.Size() == 0 {
		return spooledFile{}, fmt.Errorf("%s from the build runner is empty", name)
	}
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		return spooledFile{}, err
	}
	dst := filepath.Join(spoolDir, name)
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return spooledFile{}, err
	}
	digest := sha256.New()
	written, err := io.Copy(io.MultiWriter(out, digest), io.LimitReader(in, limit+1))
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return spooledFile{}, err
	}
	if written > limit {
		return spooledFile{}, fmt.Errorf("%s from the build runner grew past the %d byte limit while it was read", name, limit)
	}
	return spooledFile{Path: dst, SHA256: hex.EncodeToString(digest.Sum(nil)), Size: written}, nil
}

// readResult 读执行进程写的 result.json（同样按不可信数据处理）。
func readResult(layout jobspec.Layout, kind jobspec.Kind) (jobspec.Result, error) {
	in, err := os.OpenFile(layout.OutFile(jobspec.ResultFileName), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return jobspec.Result{}, fmt.Errorf("the build runner wrote no result: %w", err)
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return jobspec.Result{}, err
	}
	if !info.Mode().IsRegular() {
		return jobspec.Result{}, errors.New("the build runner result is not a regular file")
	}
	result, err := jobspec.DecodeResult(in, kind)
	if err != nil {
		return result, fmt.Errorf("the build runner result is refused: %w", err)
	}
	return result, nil
}

// checkSBOMBinding 确认 SBOM 绑定的是这个未签名包：metadata.component 的 SHA-256 是它的
// sha256，属性 rn-app:artifact 是它的文件名，rn-app:artifact-signing 是 unsigned
// （RN-App scripts/build-sbom.mjs 的 bindToArtifact）。读的是 spool 里的副本，只当 JSON 数据解析。
func checkSBOMBinding(sbomPath, unsignedSHA256, artifactName string) error {
	raw, err := os.ReadFile(sbomPath)
	if err != nil {
		return err
	}
	var document struct {
		BOMFormat string `json:"bomFormat"`
		Metadata  struct {
			Component struct {
				Hashes []struct {
					Alg     string `json:"alg"`
					Content string `json:"content"`
				} `json:"hashes"`
			} `json:"component"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return fmt.Errorf("the SBOM is not valid JSON: %w", err)
	}
	if document.BOMFormat != "CycloneDX" {
		return errors.New("the SBOM is not a CycloneDX document")
	}
	hashBound := false
	for _, hash := range document.Metadata.Component.Hashes {
		if strings.EqualFold(hash.Alg, "SHA-256") && strings.ToLower(hash.Content) == unsignedSHA256 {
			hashBound = true
		}
	}
	if !hashBound {
		return errors.New("the SBOM is not bound to this unsigned package's sha256")
	}
	properties := map[string][]string{}
	for _, property := range document.Metadata.Properties {
		properties[property.Name] = append(properties[property.Name], property.Value)
	}
	if values := properties["rn-app:artifact"]; len(values) != 1 || values[0] != artifactName {
		return fmt.Errorf("the SBOM property rn-app:artifact must name %s", artifactName)
	}
	if values := properties["rn-app:artifact-signing"]; len(values) != 1 || values[0] != "unsigned" {
		return errors.New("the SBOM property rn-app:artifact-signing must say unsigned")
	}
	return nil
}
