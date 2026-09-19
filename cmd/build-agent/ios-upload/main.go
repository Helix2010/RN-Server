// ios-upload 把一个 .ipa 传进 App Store Connect。
//
// 它以**上传账户**（_rnuploader）运行，由构建控制进程经 sudo 调起：
//
//	sudo -n -u _rnuploader /opt/rn-build-agent/ios-upload \
//	    --team <TEAMID> --keys /var/rn-build-upload \
//	    --expect-bundle-id com.x.y --expect-version 1.3.7 --expect-build 33   # 包走标准输入
//	sudo -n -u _rnuploader /opt/rn-build-agent/ios-upload --probe --team <TEAMID> --keys … --expect-bundle-id …
//	sudo -n -u _rnuploader /opt/rn-build-agent/ios-upload --install-key --keys /var/rn-build-upload   # 密文走标准输入
//
// 为什么是单独一个程序、单独一个账户（设计 ios-mac-builders-home-network-2026-09-18 §4.3）：
// 这台 Mac 的钥匙串里有全部租户的 Distribution 私钥，而执行进程跑的是几千个第三方依赖。
// 一把能上传 build 的 App Store Connect Key 正是那些签名材料唯一缺的出口，所以它既不在
// 执行进程手里，也不在持有机器令牌的控制进程手里——只有这个账户读得到
// /var/rn-build-upload/<TEAMID>/ 下的 .p8。
//
// 包走**标准输入**而不是路径：控制进程手里那份副本在它的状态目录下（0700，同一棵树里
// 放着出处私钥），给另一个账户开一条能读到那里的路，等于为了传一个不是机密的包放宽一个
// 装着机密的目录。
//
// 结果是一行 JSON（stdout），进度与错误走 stderr：
//
//	{"uploaded":true,"uploadedByEarlierAttempt":false,"detail":"…","probe":""}
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/ascapi"
)

// outcome 是打给控制进程的那一行 JSON。字段与控制进程的严格解析一一对应。
type outcome struct {
	Uploaded                 bool   `json:"uploaded"`
	UploadedByEarlierAttempt bool   `json:"uploadedByEarlierAttempt"`
	Detail                   string `json:"detail"`
	Probe                    string `json:"probe"`
}

const (
	probeOK        = "ok"
	probeForbidden = "forbidden"
	probeError     = "error"
)

var (
	appleTeamIDPattern = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	bundleIDPattern    = regexp.MustCompile(`^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$`)
	versionPattern     = regexp.MustCompile(`^[0-9]+(\.[0-9]+){0,2}$`)
	buildPattern       = regexp.MustCompile(`^[0-9]{1,10}$`)
	// keyIDPattern：Apple 的 Key ID 是 10 位大写字母数字，用它拼文件名之前先校验
	keyIDPattern = regexp.MustCompile(`^[A-Z0-9]{10}$`)
)

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	set := flag.NewFlagSet("ios-upload", flag.ContinueOnError)
	set.SetOutput(stderr)
	probe := set.Bool("probe", false, "only check whether this key may use the build upload endpoints")
	install := set.Bool("install-key", false, "install an upload key handed over as ciphertext on stdin")
	team := set.String("team", "", "Apple Developer Team ID")
	keys := set.String("keys", "/var/rn-build-upload", "directory that holds <TEAMID>/key.json and the .p8")
	bundleID := set.String("expect-bundle-id", "", "bundle id of the app this package belongs to")
	version := set.String("expect-version", "", "CFBundleShortVersionString of this package")
	build := set.String("expect-build", "", "CFBundleVersion of this package")
	baseURL := set.String("base-url", "", "App Store Connect base URL; empty = Apple's own (tests only)")
	if err := set.Parse(args); err != nil || set.NArg() != 0 {
		return 2
	}
	// 装 Key 那条路不需要 --team / --expect-*：要装什么全写在密文里，而那一份是
	// 平台在离线机器或浏览器里封的，比命令行上的值可信
	if *install {
		if err := installKey(stdin, stdout, *keys); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	switch {
	case !appleTeamIDPattern.MatchString(*team):
		fmt.Fprintln(stderr, "--team must be a 10-character Apple Developer Team ID")
		return 2
	case !bundleIDPattern.MatchString(*bundleID):
		fmt.Fprintln(stderr, "--expect-bundle-id must be a bundle id")
		return 2
	case !*probe && !versionPattern.MatchString(*version):
		fmt.Fprintln(stderr, "--expect-version must be a version like 1.3.7")
		return 2
	case !*probe && !buildPattern.MatchString(*build):
		fmt.Fprintln(stderr, "--expect-build must be the CFBundleVersion, a number")
		return 2
	}
	key, err := readKey(filepath.Join(*keys, *team))
	if err != nil {
		if *probe {
			return report(stdout, outcome{Probe: probeError, Detail: err.Error()})
		}
		fmt.Fprintln(stderr, err)
		return 1
	}
	uploader := ascapi.Uploader{Client: ascapi.Client{Key: key, BaseURL: *baseURL}}
	ctx := context.Background()
	if *probe {
		return report(stdout, probeUploads(ctx, uploader.Client, *bundleID))
	}
	result, err := upload(ctx, uploader, stdin, stderr, *bundleID, *version, *build)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return report(stdout, result)
}

func report(stdout io.Writer, result outcome) int {
	raw, err := json.Marshal(result)
	if err != nil {
		return 1
	}
	fmt.Fprintln(stdout, string(raw))
	return 0
}

// probeUploads 只读地问一次"这把 Key 能不能用这套端点"。
//
// 它**永远以 0 退出**：探测本身失败不是这台机器的故障，结果要能报到控制台上让人看见。
// forbidden 的处理是把这台 Mac 这个 Team 的 Key 换成 App Manager 角色的团队密钥（§4.3a）。
func probeUploads(ctx context.Context, client ascapi.Client, bundleID string) outcome {
	app, err := client.FindApp(ctx, bundleID)
	if err != nil {
		if errors.Is(err, ascapi.ErrKeyRejected) {
			return outcome{Probe: probeForbidden, Detail: err.Error()}
		}
		return outcome{Probe: probeError, Detail: err.Error()}
	}
	switch err := client.ProbeBuildUploads(ctx, app.ID); {
	case err == nil:
		return outcome{Probe: probeOK, Detail: "this key may use the build upload endpoints"}
	case errors.Is(err, ascapi.ErrUploadForbidden), errors.Is(err, ascapi.ErrKeyRejected):
		return outcome{Probe: probeForbidden, Detail: err.Error()}
	default:
		return outcome{Probe: probeError, Detail: err.Error()}
	}
}

func upload(ctx context.Context, uploader ascapi.Uploader, stdin io.Reader, stderr io.Writer, bundleID, version, build string) (outcome, error) {
	app, err := uploader.FindApp(ctx, bundleID)
	if err != nil {
		return outcome{}, fmt.Errorf("cannot find the App Store Connect record for %s: %w", bundleID, err)
	}
	// 先查一次同号（§6.3 第 1 步）：任务被回收重排后 build 号不变，上一次尝试可能已经
	// 传完了。省的是几百 MB 的上行，不是正确性——预查会漏，真正兜住的是下面的
	// ErrBuildAlreadyExists
	if existing, found, err := uploader.FindBuildByVersion(ctx, app.ID, build); err != nil {
		fmt.Fprintf(stderr, "cannot check whether build %s is already there: %v\n", build, err)
	} else if found {
		return outcome{Uploaded: true, UploadedByEarlierAttempt: true,
			Detail: fmt.Sprintf("build %s is already on App Store Connect (%s); not uploading again", build, existing.ProcessingState)}, nil
	}
	// 包落到自己的临时文件：分块上传要按偏移读，而标准输入只能顺着读一遍
	spooled, size, err := spool(stdin)
	if err != nil {
		return outcome{}, err
	}
	defer os.Remove(spooled.Name())
	defer spooled.Close()
	fmt.Fprintf(stderr, "uploading %d bytes for %s %s (build %s)\n", size, bundleID, version, build)

	uploadID, err := uploader.CreateBuildUpload(ctx, app.ID, version, build)
	if err != nil {
		if errors.Is(err, ascapi.ErrBuildAlreadyExists) {
			return outcome{Uploaded: true, UploadedByEarlierAttempt: true, Detail: err.Error()}, nil
		}
		return outcome{}, err
	}
	fileName := fmt.Sprintf("%s-%s-build%s.ipa", strings.ReplaceAll(bundleID, ".", "-"), version, build)
	fileID, operations, err := uploader.CreateBuildUploadFile(ctx, uploadID, fileName, size)
	if err != nil {
		if errors.Is(err, ascapi.ErrBuildAlreadyExists) {
			return outcome{Uploaded: true, UploadedByEarlierAttempt: true, Detail: err.Error()}, nil
		}
		return outcome{}, err
	}
	for index, operation := range operations {
		if err := uploadPart(ctx, uploader, spooled, operation); err != nil {
			return outcome{}, fmt.Errorf("part %d of %d: %w", index+1, len(operations), err)
		}
		fmt.Fprintf(stderr, "part %d/%d done (%d bytes)\n", index+1, len(operations), operation.Length)
	}
	if err := uploader.CompleteBuildUploadFile(ctx, fileID); err != nil {
		return outcome{}, err
	}
	return outcome{Uploaded: true, Detail: fmt.Sprintf("uploaded build %s of %s", build, bundleID)}, nil
}

// uploadPart 传一块，失败重试。家用上行断一下是常态，而重传一块比重传整个包便宜——
// 这正是这套端点比 altool 强的地方。
func uploadPart(ctx context.Context, uploader ascapi.Uploader, file *os.File, operation ascapi.UploadOperation) error {
	var last error
	for attempt := 1; attempt <= 3; attempt++ {
		section := io.NewSectionReader(file, operation.Offset, operation.Length)
		if last = uploader.UploadPart(ctx, operation, section); last == nil {
			return nil
		}
		if ctx.Err() != nil {
			return last
		}
		time.Sleep(time.Duration(attempt) * 2 * time.Second)
	}
	return last
}

// spool 把标准输入落到一个临时文件里，返回文件与字节数。
func spool(stdin io.Reader) (*os.File, int64, error) {
	file, err := os.CreateTemp("", "rn-ios-upload-*.ipa")
	if err != nil {
		return nil, 0, fmt.Errorf("cannot create a temporary file for the package: %w", err)
	}
	size, err := io.Copy(file, stdin)
	if err != nil {
		file.Close()
		os.Remove(file.Name())
		return nil, 0, fmt.Errorf("cannot read the package from standard input: %w", err)
	}
	if size == 0 {
		file.Close()
		os.Remove(file.Name())
		return nil, 0, errors.New("the package on standard input is empty")
	}
	return file, size, nil
}

// readKey 读这个 Team 的上传密钥：key.json 的 issuerId / keyId，与它旁边的 .p8。
//
// **私钥只在这个进程里**：它不进环境变量、不进命令行、不打印。ascapi.Key 的 String /
// LogValue 都不打印它。
func readKey(dir string) (ascapi.Key, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "key.json"))
	if err != nil {
		return ascapi.Key{}, fmt.Errorf("cannot read the upload key for this team: %w", err)
	}
	var meta struct {
		IssuerID string `json:"issuerId"`
		KeyID    string `json:"keyId"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&meta); err != nil {
		return ascapi.Key{}, fmt.Errorf("%s/key.json must hold exactly issuerId and keyId: %w", dir, err)
	}
	if strings.TrimSpace(meta.IssuerID) == "" || !keyIDPattern.MatchString(meta.KeyID) {
		return ascapi.Key{}, fmt.Errorf("%s/key.json has no usable issuerId / keyId", dir)
	}
	private, err := os.ReadFile(filepath.Join(dir, "AuthKey_"+meta.KeyID+".p8"))
	if err != nil {
		return ascapi.Key{}, fmt.Errorf("cannot read AuthKey_%s.p8 next to key.json: %w", meta.KeyID, err)
	}
	if _, err := ascapi.ParsePrivateKey(string(private)); err != nil {
		return ascapi.Key{}, fmt.Errorf("AuthKey_%s.p8 is not a usable App Store Connect private key: %w", meta.KeyID, err)
	}
	return ascapi.Key{IssuerID: meta.IssuerID, KeyID: meta.KeyID, PrivateKeyPEM: string(private)}, nil
}
