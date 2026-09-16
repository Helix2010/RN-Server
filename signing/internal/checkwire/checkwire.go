// Package checkwire 是签名闸主进程与检查进程之间的线协议。
//
// 请求：策略输入 JSON 一行（以 \n 结束，至多 1 MiB）+ 恰好 input.apkSize 个字节的 APK，
// 然后发送方关闭写端（管道 close / unix socket shutdown(SHUT_WR)）。
// 响应：结论 JSON 一行（至多 1 MiB），然后检查进程退出。
//
// 检查进程不信任请求里的任何东西：输入行限长、APK 限长、APK 之后必须紧跟 EOF。
package checkwire

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Helix2010/RN-Server/signing/apk"
	"github.com/Helix2010/RN-Server/signing/policy"
)

const (
	// MaxInputLine 是策略输入行的上限。
	MaxInputLine = 1 << 20
	// MaxVerdict 是结论行的上限。
	MaxVerdict = 1 << 20
)

// WriteRequest 写请求。调用方写完后关闭写端。
func WriteRequest(w io.Writer, in policy.Input, apk io.Reader) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	if len(raw)+1 > MaxInputLine {
		return errors.New("checkwire: policy input is larger than 1 MiB")
	}
	if _, err := w.Write(append(raw, '\n')); err != nil {
		return err
	}
	n, err := io.Copy(w, io.LimitReader(apk, in.APKSize+1))
	if err != nil {
		return err
	}
	if n != in.APKSize {
		return fmt.Errorf("checkwire: sent %d APK bytes, input says %d", n, in.APKSize)
	}
	return nil
}

// ReadInput 读请求的第一行并严格解析。
func ReadInput(r *bufio.Reader) (policy.Input, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > MaxInputLine {
			return policy.Input{}, errors.New("checkwire: policy input line is larger than 1 MiB")
		}
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return policy.Input{}, fmt.Errorf("checkwire: reading the policy input: %w", err)
	}
	var in policy.Input
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&in); err != nil {
		return policy.Input{}, fmt.Errorf("checkwire: policy input is not valid JSON: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return policy.Input{}, errors.New("checkwire: trailing data on the policy input line")
	}
	return in, nil
}

// CopyAPK 把恰好 size 个字节拷到 dst，并确认之后是 EOF。
func CopyAPK(dst io.Writer, r *bufio.Reader, size int64) error {
	n, err := io.Copy(dst, io.LimitReader(r, size))
	if err != nil {
		return fmt.Errorf("checkwire: reading the APK: %w", err)
	}
	if n != size {
		return fmt.Errorf("checkwire: received %d APK bytes, expected %d", n, size)
	}
	if _, err := r.ReadByte(); err != io.EOF {
		return errors.New("checkwire: unexpected data after the APK")
	}
	return nil
}

// Serve 是检查进程的全部工作：读请求、把 APK 写进自己的临时目录、执行检查、写结论。
// 返回进程退出码：0 表示写出了结论（通过或拒签），2 表示请求不合法或本地故障（没有结论）。
func Serve(stdin io.Reader, stdout, stderr io.Writer) int {
	limits := apk.DefaultLimits()
	reader := bufio.NewReaderSize(stdin, 64<<10)
	in, err := ReadInput(reader)
	if err != nil {
		fmt.Fprintln(stderr, "signer-check:", err)
		return 2
	}
	if in.APKSize < 1 || in.APKSize > limits.MaxFileSize {
		fmt.Fprintf(stderr, "signer-check: apkSize %d is outside 1..%d\n", in.APKSize, limits.MaxFileSize)
		return 2
	}
	dir, err := os.MkdirTemp("", "signer-check-")
	if err != nil {
		fmt.Fprintln(stderr, "signer-check: temporary directory:", err)
		return 2
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "unsigned.apk")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fmt.Fprintln(stderr, "signer-check: temporary file:", err)
		return 2
	}
	if err := CopyAPK(f, reader, in.APKSize); err != nil {
		f.Close()
		fmt.Fprintln(stderr, "signer-check:", err)
		return 2
	}
	if err := f.Close(); err != nil {
		fmt.Fprintln(stderr, "signer-check: temporary file:", err)
		return 2
	}
	verdict := policy.EvaluateFile(in, path, limits)
	if err := WriteVerdict(stdout, verdict); err != nil {
		fmt.Fprintln(stderr, "signer-check: writing the verdict:", err)
		return 2
	}
	return 0
}

// WriteVerdict 写结论行。
func WriteVerdict(w io.Writer, v policy.Verdict) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(raw, '\n'))
	return err
}

// ReadVerdict 读结论：恰好一行 JSON，随后 EOF。
func ReadVerdict(r io.Reader) (policy.Verdict, error) {
	raw, err := io.ReadAll(io.LimitReader(r, MaxVerdict+1))
	if err != nil {
		return policy.Verdict{}, fmt.Errorf("checkwire: reading the verdict: %w", err)
	}
	if len(raw) > MaxVerdict {
		return policy.Verdict{}, errors.New("checkwire: verdict is larger than 1 MiB")
	}
	if len(raw) == 0 || raw[len(raw)-1] != '\n' || bytes.Count(raw, []byte("\n")) != 1 {
		return policy.Verdict{}, errors.New("checkwire: the checker did not return exactly one verdict line")
	}
	var v policy.Verdict
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&v); err != nil {
		return policy.Verdict{}, fmt.Errorf("checkwire: verdict is not valid JSON: %w", err)
	}
	if v.OK && (v.Kind != "" || v.Code != "" || v.Facts == nil) {
		return policy.Verdict{}, errors.New("checkwire: an OK verdict must carry facts and no rejection")
	}
	if !v.OK && (v.Kind != policy.KindViolation && v.Kind != policy.KindDeferred || v.Code == "") {
		return policy.Verdict{}, errors.New("checkwire: a rejection must carry a kind and a code")
	}
	return v, nil
}
