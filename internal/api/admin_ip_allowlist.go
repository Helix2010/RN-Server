package api

// x-admin-key 自动化通道的来源限制（安全评审 N17）。
//
// 这条通道绕过账号登录：一把长期有效的静态密钥，谁拿到谁就是管理员。评审给的建议是
// "没有调用方就删，有就绑定固定 actor 白名单与来源 IP"。actor 已经绑死在配置里、
// 不再采信请求自报的身份；这里补上来源。
//
// **一个前提不能绕过：来源 IP 必须是可信的。** gin 默认信任所有代理，也就是任何人
// 都能用 X-Forwarded-For 声称自己来自任何地址。在那种情况下"IP 白名单"看起来像一道门，
// 实际上谁都能推开——比没有门更糟，因为它会让人以为这件事做完了。所以配了白名单却
// 没配可信代理时，服务端**拒绝启动**。

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

type ipAllowlist struct {
	nets []*net.IPNet
	ips  []net.IP
}

// parseIPAllowlist 接受 CIDR 或裸 IP。空列表表示不限制。
func parseIPAllowlist(entries []string) (*ipAllowlist, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	list := &ipAllowlist{}
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if strings.Contains(entry, "/") {
			_, network, err := net.ParseCIDR(entry)
			if err != nil {
				return nil, fmt.Errorf("admin ip allowlist: %q is not a CIDR: %w", entry, err)
			}
			list.nets = append(list.nets, network)
			continue
		}
		ip := net.ParseIP(entry)
		if ip == nil {
			return nil, fmt.Errorf("admin ip allowlist: %q is not an IP or CIDR", entry)
		}
		list.ips = append(list.ips, ip)
	}
	return list, nil
}

// allows 判断一个来源地址是否在名单里。nil 名单放行一切（未配置）。
func (l *ipAllowlist) allows(clientIP string) bool {
	if l == nil {
		return true
	}
	ip := net.ParseIP(strings.TrimSpace(clientIP))
	if ip == nil {
		// 解析不出来就是不放行：这条通道宁可挡错，也不能因为一个畸形的地址就放开
		return false
	}
	for _, known := range l.ips {
		if known.Equal(ip) {
			return true
		}
	}
	for _, network := range l.nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// errAllowlistWithoutTrustedProxies 是启动期的自检：见文件头。
var errAllowlistWithoutTrustedProxies = errors.New(
	"ADMIN_API_ALLOWED_IPS is set but TRUSTED_PROXIES is not: the client IP would be attacker-controlled and the allowlist would be decorative",
)

func validateAdminIPConfiguration(allowed, trustedProxies []string) error {
	if len(allowed) > 0 && len(trustedProxies) == 0 {
		return errAllowlistWithoutTrustedProxies
	}
	return nil
}
