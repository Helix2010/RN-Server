package main

// 签名材料的自动装配（设计 ios-signing-material-distribution-2026-09-19.md §6.2）。
//
// 控制进程做的事只有搬运：取清单、比对本机已经装到第几版、把新的那几份**密文**交给对应
// 角色的程序。**它不解密，也解不开**——两把私钥分别在 _rnbuilder 与 _rnuploader 名下，
// 而它持有的是机器令牌与出处密钥。这条界线就是 Mac 上三个账户分开的理由（§4.1）。
//
// 密文走标准输入交过去，不落盘：控制进程的状态目录 0700、同一棵树里放着出处私钥，为了
// 递一份不是机密的密文去放宽那个目录不值得。

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
	"github.com/Helix2010/RN-Server/signing/iosmaterial"
)

// installedMaterialFile 记本机每一格材料装到了第几版。
//
// 记在控制进程这一侧而不是问两个角色账户："装到了第几版"是个调度问题，不是材料本身的
// 属性；而且问它们等于每一轮都要多起两个子进程。
const installedMaterialFile = "ios-material.json"

// iosMaterialSyncEvery 是两次取清单之间的最短间隔。认领每 10 秒一次，而材料几个月才
// 动一次——每一轮都去问一次纯属浪费，服务端那边也是。
const iosMaterialSyncEvery = 2 * time.Minute

// materialEntry 是清单里的一项，与服务端 storedIOSMaterial 对齐。
type materialEntry struct {
	Kind            string `json:"kind"`
	TeamID          string `json:"teamId"`
	Scope           string `json:"scope"`
	Purpose         string `json:"purpose"`
	RecipientSHA256 string `json:"recipientSha256"`
	Version         int64  `json:"version"`
}

// slot 是这一格在本机记录里的键。
func (e materialEntry) slot() string { return e.Kind + "/" + e.TeamID + "/" + e.Scope }

// syncIOSMaterial 取一次清单，把还没装或版本更高的那几份装上。
//
// 失败不是致命错误：这一轮装不上，下一轮再来。装不上的后果是"这台机器少报一个 Team"，
// 而那件事控制台上看得见（missingTenants）——比在这里把认领循环卡住好。
func (a *agent) syncIOSMaterial(ctx context.Context) {
	if a.cfg.MachineEnv[jobspec.IOSSigningDirEnv] == "" {
		return // 不是 iOS 打包机
	}
	if !a.materialDue() {
		return
	}
	entries, err := a.api.iosMaterial(ctx)
	if err != nil {
		a.sayOnce("iosMaterialList", "cannot read the signing material list: "+err.Error())
		return
	}
	installed := readInstalledMaterial(a.cfg.StateDir)
	changed := false
	for _, entry := range entries {
		if have, ok := installed[entry.slot()]; ok && have >= entry.Version {
			continue
		}
		if err := a.installMaterial(ctx, entry); err != nil {
			// 一份装不上不该挡住别的：证书没装上时描述文件照样该放好，人能从控制台上
			// 看出缺的是哪一片
			a.log.Error("cannot install signing material", "slot", entry.slot(), "error", err)
			continue
		}
		a.log.Info("signing material installed", "slot", entry.slot(), "version", entry.Version)
		installed[entry.slot()] = entry.Version
		changed = true
	}
	// 墓碑：本机从服务端装过、而清单里这个 Team 已经没有上传 Key 了（租户切到自助上传、Key 被撤下）
	// ——请上传账户把本机那一份删掉。服务端删材料只删它自己的密文，不这样做的话，切到自助上传的
	// 租户的 Key 会一直留在每台 Mac 上（设计 ios-tenant-delivery-tiers-2026-09-24 §3.9）。
	// 只动本机从清单装上的那几格：装机时手工放的 Key 不在记录里，不碰
	if removed := a.removeWithdrawnUploadKeys(ctx, entries, installed); removed {
		changed = true
	}
	if changed {
		if err := writeInstalledMaterial(a.cfg.StateDir, installed); err != nil {
			// 记不下来的后果是下一轮重装一遍——幂等，但会白跑两个子进程
			a.log.Error("cannot record which signing material is installed", "error", err)
		}
	}
}

// removeWithdrawnUploadKeys 删掉清单里已经没有的上传 Key，返回是否改了本机记录。
func (a *agent) removeWithdrawnUploadKeys(ctx context.Context, entries []materialEntry, installed map[string]int64) bool {
	listed := map[string]bool{}
	for _, entry := range entries {
		if entry.Kind == iosmaterial.KindUploadKey {
			listed[entry.TeamID] = true
		}
	}
	changed := false
	for slot := range installed {
		kind, rest, _ := strings.Cut(slot, "/")
		team, _, _ := strings.Cut(rest, "/")
		if kind != iosmaterial.KindUploadKey || listed[team] {
			continue
		}
		if err := a.removeUploadKey(ctx, team); err != nil {
			a.log.Error("cannot remove a withdrawn upload key", "team", team, "error", err)
			continue
		}
		a.log.Info("withdrawn upload key removed", "team", team)
		delete(installed, slot)
		changed = true
	}
	return changed
}

// removeUploadKey 请上传账户删掉一个 Team 的上传 Key。
func (a *agent) removeUploadKey(ctx context.Context, team string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cmd := a.uploaderCommand(ctx, "--remove-key", "--team", team, "--keys", a.cfg.IOSUploadKeys)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, truncate(strings.TrimSpace(stderr.String()), 300))
	}
	var result struct {
		Removed bool `json:"removed"`
	}
	if json.Unmarshal(stdout.Bytes(), &result) != nil || !result.Removed {
		return fmt.Errorf("the upload program did not confirm: %s", truncate(stdout.String(), 200))
	}
	return nil
}

// materialDue 控制取清单的频率。
func (a *agent) materialDue() bool {
	now := a.now()
	if !a.lastMaterialSync.IsZero() && now.Sub(a.lastMaterialSync) < iosMaterialSyncEvery {
		return false
	}
	a.lastMaterialSync = now
	return true
}

// installMaterial 取一份密文，交给对应角色的程序装。
func (a *agent) installMaterial(ctx context.Context, entry materialEntry) error {
	ciphertext, err := a.api.iosMaterialBox(ctx, entry)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var cmd = a.runnerReadCommand(ctx, "install-ios-material",
		"--signing-dir", a.cfg.MachineEnv[jobspec.IOSSigningDirEnv])
	if entry.Purpose == iosmaterial.PurposeUploader {
		cmd = a.uploaderCommand(ctx, "--install-key", "--keys", a.cfg.IOSUploadKeys)
	}
	cmd.Stdin = bytes.NewReader(ciphertext)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, truncate(runnerFailureDetail(stdout.String(), stderr.String()), 300))
	}
	out := stdout.Bytes()
	var result struct {
		Installed bool `json:"installed"`
	}
	if json.Unmarshal(out, &result) != nil || !result.Installed {
		return fmt.Errorf("the installer did not confirm: %s", truncate(string(out), 200))
	}
	return nil
}

// ---- 本机记录 ----

func readInstalledMaterial(stateDir string) map[string]int64 {
	out := map[string]int64{}
	raw, err := os.ReadFile(filepath.Join(stateDir, installedMaterialFile))
	if err != nil {
		return out
	}
	if json.Unmarshal(raw, &out) != nil {
		// 读不出来当作什么都没装：重装一遍是幂等的，而拿着一份坏记录会永远跳过
		return map[string]int64{}
	}
	return out
}

func writeInstalledMaterial(stateDir string, installed map[string]int64) error {
	raw, err := json.Marshal(installed)
	if err != nil {
		return err
	}
	path := filepath.Join(stateDir, installedMaterialFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// ---- 服务端那两条 ----

// iosMaterial 取这台机器该装的材料清单。
func (c *client) iosMaterial(ctx context.Context) ([]materialEntry, error) {
	_, payload, err := c.send(ctx, "GET", "/v1/build-agent/ios-material", 0, nil)
	if err != nil {
		return nil, err
	}
	var body struct {
		Items []materialEntry `json:"items"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		return nil, fmt.Errorf("the signing material list is not JSON: %w", err)
	}
	return body.Items, nil
}

// iosMaterialBox 取一份密文，原样返回。控制进程不解析它，也解不开。
func (c *client) iosMaterialBox(ctx context.Context, entry materialEntry) ([]byte, error) {
	query := url.Values{"kind": {entry.Kind}, "teamId": {entry.TeamID}, "scope": {entry.Scope}}
	_, payload, err := c.send(ctx, "GET", "/v1/build-agent/ios-material/box?"+query.Encode(), 0, nil)
	return payload, err
}
