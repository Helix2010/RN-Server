// Package netproxy 是打包机的出网代理：env 文件里只配一次（BUILD_AGENT_PROXY），
// 这里按每个使用方要的形状展开。
//
// 为什么不让人直接在 env 文件里写 HTTPS_PROXY 那一套：
//
//   - 各个工具认的键不一样。libcurl 只认小写的 `http_proxy`，`HTTPS_PROXY` 大小写都认，
//     Go 两种都认，pnpm 还有自己的一套。人手写八个键，漏一个就是"某些工具走代理、某些
//     不走"——最难查的那种半通。
//   - 有一个使用方根本拿不到环境变量：上传程序经 sudo 切到上传账户启动，sudoers 里是
//     NOSETENV，环境整个被清掉（这是有意的，见 rn-build-agent.sudoers）。它的代理只能
//     走命令行参数。2026-09-23 真机上撞到：env 文件就算配了代理，上传照样直连
//     api.appstoreconnect.apple.com，TCP 超时。
//
// 所以代理是一个键进来，由控制进程分发：构建进程拿到八个环境变量，上传程序拿到
// --proxy / --no-proxy，控制进程自己的 HTTP 客户端直接设 Transport.Proxy。
package netproxy

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/http/httpproxy"
)

// EnvKeys 是各工具认的代理变量，大小写两套。控制进程拒绝 env 文件里直接写这些键——
// 代理只从 BUILD_AGENT_PROXY 一个地方来。
var EnvKeys = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
	"http_proxy", "https_proxy", "all_proxy", "no_proxy",
}

// alwaysDirect 永远不走代理。代理本身多半就在本机（Clash 之类），经代理去连代理是个环。
var alwaysDirect = []string{"localhost", "127.0.0.1", "::1"}

var (
	// urlPattern：scheme://host[:port]，**不许带用户名口令**。构建进程的环境对它跑的
	// 第三方依赖是可读的，把 `http://user:pass@…` 放进去等于把那组凭据交给它们。
	// 要认证的代理请在机器上用别的方式做（本机转发、系统级配置）。
	urlPattern = regexp.MustCompile(`^(?:https?|socks5h?)://[A-Za-z0-9._-]+(?::[0-9]{1,5})?/?$`)
	// noProxyPattern：逗号分隔的主机、域名、网段
	noProxyPattern = regexp.MustCompile(`^[A-Za-z0-9.,:*_/-]*$`)
)

// ValidURL 校验代理地址的形状。
func ValidURL(value string) error {
	if !urlPattern.MatchString(value) {
		return errors.New("the proxy must be scheme://host[:port] (http, https, socks5 or socks5h) with no credentials in it " +
			"(the build environment is readable by the third-party code a build runs)")
	}
	return nil
}

// ValidNoProxy 校验不走代理的主机列表。
func ValidNoProxy(value string) error {
	if !noProxyPattern.MatchString(value) {
		return errors.New("the no-proxy list must be comma-separated hosts, domains or networks")
	}
	return nil
}

// Config 是校验过的代理配置。零值 = 不用代理。
type Config struct {
	// URL 为空表示不用代理
	URL string
	// NoProxy 是规范化后的列表（逗号分隔、去重），总是含 localhost 与回环地址
	NoProxy string
}

// New 校验并组装配置。direct 是调用方要求一定直连的主机（比如打包机自己的服务端）。
// proxyURL 为空时返回零值：不用代理，noProxy 与 direct 都不看。
func New(proxyURL, noProxy string, direct ...string) (Config, error) {
	proxyURL = strings.TrimSpace(proxyURL)
	if proxyURL == "" {
		return Config{}, nil
	}
	if err := ValidURL(proxyURL); err != nil {
		return Config{}, err
	}
	// 逐个主机校验（去掉空白之后）：人写 env 文件时逗号后面习惯带空格
	seen := map[string]bool{}
	var hosts []string
	for _, group := range [][]string{alwaysDirect, direct, strings.Split(noProxy, ",")} {
		for _, host := range group {
			host = strings.ToLower(strings.TrimSpace(host))
			if host == "" || seen[host] {
				continue
			}
			if err := ValidNoProxy(host); err != nil {
				return Config{}, fmt.Errorf("%q: %w", host, err)
			}
			seen[host] = true
			hosts = append(hosts, host)
		}
	}
	return Config{URL: strings.TrimRight(proxyURL, "/"), NoProxy: strings.Join(hosts, ",")}, nil
}

// Enabled 说明配了代理。
func (c Config) Enabled() bool { return c.URL != "" }

// Env 是给构建进程的环境变量，八个键一个不少。不用代理时为空。
func (c Config) Env() map[string]string {
	env := map[string]string{}
	if !c.Enabled() {
		return env
	}
	for _, key := range EnvKeys {
		if strings.EqualFold(key, "NO_PROXY") {
			env[key] = c.NoProxy
		} else {
			env[key] = c.URL
		}
	}
	return env
}

// Args 是给上传程序的命令行参数。不用代理时为空。
func (c Config) Args() []string {
	if !c.Enabled() {
		return nil
	}
	return []string{"--proxy", c.URL, "--no-proxy", c.NoProxy}
}

// Func 是 http.Transport 的 Proxy 字段。不用代理时返回 nil——**直连，而且不看进程
// 环境**：代理只从这份配置来，不让一个遗留的环境变量悄悄改变出网路径。
func (c Config) Func() func(*http.Request) (*url.URL, error) {
	if !c.Enabled() {
		return nil
	}
	resolve := (&httpproxy.Config{HTTPProxy: c.URL, HTTPSProxy: c.URL, NoProxy: c.NoProxy}).ProxyFunc()
	return func(request *http.Request) (*url.URL, error) { return resolve(request.URL) }
}

// Transport 返回一个按这份配置出网的 Transport（其余参数同 http.DefaultTransport）。
func (c Config) Transport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = c.Func()
	return transport
}
