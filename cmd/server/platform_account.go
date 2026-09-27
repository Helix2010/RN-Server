package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/api"
	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/store"
)

// runPlatformAccountCommand 是 `rn-server admin platform-account create|reset`
// （设计 platform-accounts-and-console-login-2026-09-27 §3.6）。
//
// 控制台里一个平台管理员都没有的时候（第一个；或者全部失效之后）只能在服务器上建。在 amos 上用与服务相同的
// 用户和 EnvironmentFile 执行，不要在 shell 里 source /etc/rn-foundation.env：
//
//	sudo systemd-run --quiet --pipe --wait -p User=rnfoundation -p EnvironmentFile=/etc/rn-foundation.env \
//	  /opt/rn-foundation/rn-server admin platform-account create --login <登录名> --email <邮箱> --name <显示名>
//
// 初始口令只打印到执行者的终端这一次：不进日志、不进审计（审计只记「谁在命令行建了、重置了哪个账号」）。
func runPlatformAccountCommand(cfg config.Config, database *store.Store, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: rn-server admin platform-account create|reset [flags]")
	}
	flags := flag.NewFlagSet("platform-account "+args[0], flag.ContinueOnError)
	login := flags.String("login", "", "login name (3-64 characters: lowercase letters, digits, . _ -)")
	email := flags.String("email", "", "the administrator's own email: second-factor codes and notices go there")
	name := flags.String("name", "", "display name (create)")
	reason := flags.String("reason", "", "why the account is reset (reset); written to the audit log")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	actor := commandActor()
	var issued *api.PlatformAccountIssued
	var err error
	switch args[0] {
	case "create":
		if *login == "" || *email == "" || *name == "" {
			return errors.New("create needs --login, --email and --name")
		}
		issued, err = api.CreatePlatformAccount(ctx, database.DB, *login, *email, *name, actor, cfg.AdminUsername)
	case "reset":
		if *login == "" {
			return errors.New("reset needs --login")
		}
		text := strings.TrimSpace(*reason)
		if text == "" {
			text = "服务器上用命令行重置"
		}
		issued, err = api.ResetPlatformAccount(ctx, database.DB, *login, text, actor)
	default:
		return fmt.Errorf("unknown platform-account command %q (want create or reset)", args[0])
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "平台管理员账号 %s（id %s，邮箱 %s）现在等待绑定统一账号。\n", issued.LoginName, issued.ID, issued.Email)
	fmt.Fprintf(out, "初始口令只显示这一次，%s 之前有效：\n\n    %s\n\n", issued.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC"), issued.InitialPassword)
	fmt.Fprintln(out, "下一步：在任意一个控制台域名上用这个登录名和初始口令登录，过邮箱二次验证，然后绑定统一账号。")
	return nil
}

// commandActor 是命令行操作在审计里的 actor：cli@<主机名>。经 systemd-run 执行时拿不到 sudo 前的用户名。
func commandActor() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown-host"
	}
	return "cli@" + host
}
