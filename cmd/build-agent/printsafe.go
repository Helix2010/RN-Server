package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"sort"
	"strings"
)

// 装着机密的结构体（本机令牌、出处私钥、脱敏器里的机密值）一律只能打印白名单里的字段：
// 新加的字段默认不出现。按 AGENTS.md「机密的操作纪律」。
//
// String / GoString / LogValue 之外还实现 Format：fmt 对 %d、%x 这类动词不会调 String，
// 而是逐字段原样打印——不实现 Format，`%d` 一样能把令牌打出来。结构体里未导出的字段
// 在外层被打印时 fmt 不调它们的方法，所以外层（agent）也要各自实现。字段导出的 config
// 还要挡 json.Marshal。

func (c config) safeSummary() string {
	envKeys := make([]string, 0, len(c.MachineEnv))
	for key := range c.MachineEnv {
		envKeys = append(envKeys, key)
	}
	sort.Strings(envKeys)
	return fmt.Sprintf("build-agent config{server=%s repo=%s workspace=%s stateDir=%s platforms=%s timeout=%s runner=%s runnerUser=%s machineEnv=[%s] machineToken=%s}",
		safeOrigin(c.Server), c.Repo, c.Workspace, c.StateDir, strings.Join(c.Platforms, ","), c.Timeout,
		c.Runner, c.RunnerUser, strings.Join(envKeys, ","), presence(c.MachineToken))
}

func (c config) String() string             { return c.safeSummary() }
func (c config) GoString() string           { return c.safeSummary() }
func (c config) LogValue() slog.Value       { return slog.StringValue(c.safeSummary()) }
func (c config) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.safeSummary()) }

// MarshalJSON 挡住 json.Marshal（slog 的 JSON handler 遇到嵌在别的结构体里的 config 就走这条）：
// config 的字段是导出的，不挡的话令牌会原样进 JSON。
func (c config) MarshalJSON() ([]byte, error) { return json.Marshal(c.safeSummary()) }

func (c *client) safeSummary() string {
	return "build-agent client{server=" + safeOrigin(c.server) + " machineToken=" + presence(c.token) + "}"
}
func (c *client) String() string                 { return c.safeSummary() }
func (c *client) GoString() string               { return c.safeSummary() }
func (c *client) LogValue() slog.Value           { return slog.StringValue(c.safeSummary()) }
func (c *client) Format(f fmt.State, _ rune)     { _, _ = io.WriteString(f, c.safeSummary()) }
func (k machineKey) safeSummary() string         { return "provenance key{publicKeySha256=" + k.sha256 + "}" }
func (k machineKey) String() string              { return k.safeSummary() }
func (k machineKey) GoString() string            { return k.safeSummary() }
func (k machineKey) LogValue() slog.Value        { return slog.StringValue(k.safeSummary()) }
func (k machineKey) Format(f fmt.State, _ rune)  { _, _ = io.WriteString(f, k.safeSummary()) }
func (r *keyring) String() string                { return r.safeSummary() }
func (r *keyring) GoString() string              { return r.safeSummary() }
func (r *keyring) LogValue() slog.Value          { return slog.StringValue(r.safeSummary()) }
func (r *keyring) Format(f fmt.State, _ rune)    { _, _ = io.WriteString(f, r.safeSummary()) }
func (r *redactor) safeSummary() string          { return fmt.Sprintf("redactor{values=%d}", len(r.values)) }
func (r *redactor) String() string               { return r.safeSummary() }
func (r *redactor) GoString() string             { return r.safeSummary() }
func (r *redactor) LogValue() slog.Value         { return slog.StringValue(r.safeSummary()) }
func (r *redactor) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, r.safeSummary()) }
func (a *agent) String() string                  { return a.safeSummary() }
func (a *agent) GoString() string                { return a.safeSummary() }
func (a *agent) LogValue() slog.Value            { return slog.StringValue(a.safeSummary()) }
func (a *agent) Format(f fmt.State, _ rune)      { _, _ = io.WriteString(f, a.safeSummary()) }
func (b *logBuffer) String() string              { return fmt.Sprintf("logBuffer{lines=%d}", len(b.snapshot())) }
func (b *logBuffer) GoString() string            { return b.String() }
func (b *logBuffer) Format(f fmt.State, _ rune)  { _, _ = io.WriteString(f, b.String()) }
func (w *lineWriter) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "lineWriter{}") }

func (e enrollment) safeSummary() string {
	return "enrollment{machineId=" + safeWord(e.MachineID) + " status=" + safeWord(e.Status) + " token=" + presence(e.Token) + "}"
}
func (e enrollment) String() string               { return e.safeSummary() }
func (e enrollment) GoString() string             { return e.safeSummary() }
func (e enrollment) LogValue() slog.Value         { return slog.StringValue(e.safeSummary()) }
func (e enrollment) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, e.safeSummary()) }
func (e enrollment) MarshalJSON() ([]byte, error) { return json.Marshal(e.safeSummary()) }

func (r *keyring) safeSummary() string {
	if r == nil {
		return "keyring{}"
	}
	next := "none"
	if r.next != nil {
		next = r.next.sha256
	}
	return "keyring{dir=" + r.dir + " current=" + r.current.sha256 + " next=" + next + "}"
}

func (a *agent) safeSummary() string {
	if a == nil {
		return "agent{}"
	}
	return "build-agent{" + a.cfg.safeSummary() + " " + a.keys.safeSummary() + "}"
}

func presence(secret string) string {
	if secret == "" {
		return "unset"
	}
	return "set"
}

// safeOrigin 只留 scheme://host：地址里万一带了 userinfo 或查询参数，也不打印出来。
func safeOrigin(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return "(unparseable)"
	}
	return parsed.Scheme + "://" + parsed.Host
}
