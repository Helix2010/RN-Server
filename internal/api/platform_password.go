package api

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"unicode"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/scrypt"
)

// 生成 ADMIN_PASSWORD_HASH。
//
// 为什么值得有这个接口：这个哈希是手工算出来写进 /etc/rn-foundation.env 的，而
// "手工算"在现实里是去网上找一个 scrypt 工具，把生产口令贴进别人的网页。这个接口
// 把那一步收回到本机。
//
// 明文确实会经过服务端——但登录本来每次都在做同一件事，所以这里没有引入新的暴露
// 面。它只是**不落任何地方**：不写日志、不进审计（审计只记"有人生成过"）、不入库。
//
// 平台级：ADMIN_USERNAME / ADMIN_PASSWORD_HASH 是整个服务端一个账号，不按租户分。
const (
	passwordHashN   = 1 << 15 // 32768，verifyPassword 允许的上限
	passwordHashR   = 8
	passwordHashP   = 1
	passwordKeyLen  = 32
	passwordSaltLen = 16
	// 这把口令背后是 platformAdmin。短口令在这里的代价和别处不一样
	minAdminPasswordLen = 16
)

func (s *server) generateAdminPasswordHash(c *gin.Context) {
	var body struct {
		Password string `json:"password"`
	}
	if decode(c, &body) != nil {
		problem(c, http.StatusBadRequest, "INVALID_PASSWORD", "password is required")
		return
	}
	// 不 TrimSpace：首尾空格是口令的一部分，悄悄改掉会让人算出一个登不进去的哈希
	password := body.Password
	if err := checkAdminPasswordStrength(password); err != nil {
		problem(c, http.StatusBadRequest, "WEAK_PASSWORD", err.Error())
		return
	}
	encoded, err := hashPassword(password)
	if err != nil {
		problem(c, http.StatusInternalServerError, "PASSWORD_HASH_FAILED", "Unable to generate a hash")
		return
	}

	// 审计只记"谁在什么时候生成过一个哈希"。口令和哈希都不进审计：审计表比配置文件
	// 好读得多，把哈希写进去等于给它多开一个离线爆破的入口
	s.auditNow(newAudit("0", actor(c), "admin_password_hash_generate", "config", "ADMIN_PASSWORD_HASH",
		"生成管理员口令哈希", requestID(c), map[string]any{"algorithm": "scrypt", "n": passwordHashN}))

	c.JSON(http.StatusOK, gin.H{
		"hash":      encoded,
		"algorithm": fmt.Sprintf("scrypt N=%d r=%d p=%d", passwordHashN, passwordHashR, passwordHashP),
		// 值里有 $，写进 .env 必须带单引号——不带的话任何 source 这个文件的脚本都会
		// 把 $32768 当变量吃掉，留下一个登不进去的哈希。这个坑踩过
		"envLine": "ADMIN_PASSWORD_HASH='" + encoded + "'",
	})
}

// hashPassword 算 verifyPassword 认的 scrypt 哈希（scrypt$N$r$p$salt$key）。平台管理员口令与租户账号的初始口令共用。
func hashPassword(password string) (string, error) {
	salt := make([]byte, passwordSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	sum, err := scrypt.Key([]byte(password), salt, passwordHashN, passwordHashR, passwordHashP, passwordKeyLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("scrypt$%d$%d$%d$%s$%s", passwordHashN, passwordHashR, passwordHashP,
		base64.RawURLEncoding.EncodeToString(salt),
		base64.RawURLEncoding.EncodeToString(sum)), nil
}

func checkAdminPasswordStrength(password string) error {
	if len([]rune(password)) < minAdminPasswordLen {
		return fmt.Errorf("password must be at least %d characters", minAdminPasswordLen)
	}
	if len(password) > 256 {
		return fmt.Errorf("password must be at most 256 bytes")
	}
	var kinds int
	for _, class := range []func(rune) bool{unicode.IsLower, unicode.IsUpper, unicode.IsDigit, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r)
	}} {
		if strings.IndexFunc(password, class) >= 0 {
			kinds++
		}
	}
	if kinds < 3 {
		return fmt.Errorf("password must mix at least three of: lowercase, uppercase, digits, symbols")
	}
	return nil
}
