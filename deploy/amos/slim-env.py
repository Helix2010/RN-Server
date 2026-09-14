#!/usr/bin/env python3
"""把 /etc/rn-foundation.env 收缩成只剩"别处不可能知道"的那些键。

做三件事，都不让任何值出现在输出里：

  1. 把 MYSQL_HOST/PORT/USER/PASSWORD/DATABASE/CHARSET/TIMEZONE/PARSE_TIME 和三个
     超时合成一行 MYSQL_DSN，然后删掉那十一行。
  2. 删掉代码从不读取的键（示例文件里躺了很久、amos 上照着填了的那几个）。
  3. 删掉**值与代码默认值完全相同**的行——写了等于没写，而它们的代价是以后没人
     能一眼看出哪些是特意设成这样的。值不等于默认的一律留着，这一步不做判断。

先跑一次不加 --apply 看要动哪些键；确认之后再加 --apply。改之前会留一份带时间戳
的备份（0600 root）。

设计见 RN-Server/docs/design/env-config-slimdown-2026-09-13.md §7。
"""

import argparse
import os
import shutil
import sys
import time
import urllib.parse

TARGET = "/etc/rn-foundation.env"

# 合进 MYSQL_DSN 的十一个键
LEGACY_MYSQL = [
    "MYSQL_HOST", "MYSQL_PORT", "MYSQL_USER", "MYSQL_PASSWORD", "MYSQL_DATABASE",
    "MYSQL_CHARSET", "MYSQL_TIMEZONE", "MYSQL_PARSE_TIME",
    "MYSQL_CONNECT_TIMEOUT_SECONDS", "MYSQL_READ_TIMEOUT_SECONDS", "MYSQL_WRITE_TIMEOUT_SECONDS",
]

# 代码从不读取，或键本身已经删掉的
DEAD = {
    "INDEXER_MYSQL_CONNECTION_LIMIT": "代码从来没读过这个键",
    "ARTIFACT_DOWNLOAD_TTL_SECONDS": "读进 Config 之后没有任何地方用",
    "OTA_CHANNEL": "只在 updatePolicy.otaChannel 缺失时兜底，而模板里那个键有值",
    "ANDROID_STORE_URL": "下载地址按租户生成，全局值不可能同时对四个租户都对",
    "ANDROID_DIRECT_URL": "同上",
    "IOS_STORE_URL": "同上",
    "IOS_MDM_URL": "同上",
}

# 代码里的默认值。只有**值完全相同**时才删。
DEFAULTS = {
    "HTTP_READ_TIMEOUT_SECONDS": "3600",
    "HTTP_WRITE_TIMEOUT_SECONDS": "3600",
    "ADMIN_API_ACTOR": "api-key-automation",
    "ADMIN_SESSION_TTL_SECONDS": "28800",
    "ADMIN_COOKIE_SECURE": "true",
    "ADMIN_LOGIN_MAX_ATTEMPTS": "5",
    "ADMIN_LOGIN_WINDOW_SECONDS": "900",
    "MYSQL_QUERY_TIMEOUT_SECONDS": "10",
    "MYSQL_INIT_TIMEOUT_SECONDS": "30",
    "MYSQL_INIT_MAX_ATTEMPTS": "3",
    "MYSQL_INIT_RETRY_DELAY_SECONDS": "5",
    "ARTIFACT_MAX_SIZE_MB": "512",
    "ARTIFACT_UPLOAD_TTL_SECONDS": "900",
    "ARTIFACT_MULTIPART_TTL_SECONDS": "7200",
    "ARTIFACT_VERIFY_TIMEOUT_SECONDS": "300",
    "PUSH_POLL_INTERVAL_SECONDS": "10",
    "PUSH_CONCURRENCY": "8",
    "APNS_ENVIRONMENT": "production",
    "INDEXER_ALLOW_PLAIN_HTTP": "false",
    # 起了 rn-foundation-indexer 这个 unit 就是要扫链，子命令的默认值已经是 true
    "INDEXER_ENABLED": "true",
}

# 空着等于没配，删掉不改变任何行为
DROP_IF_EMPTY = [
    "ADMIN_API_ALLOWED_IPS", "DEVICE_IDENTITY_HMAC_KEY", "INDEXER_ALERT_WEBHOOK",
    "APNS_TEAM_ID", "APNS_KEY_ID", "APNS_PRIVATE_KEY", "APNS_BUNDLE_ID",
    "HMS_APP_ID", "HMS_CLIENT_ID", "HMS_CLIENT_SECRET",
    "PLATFORM_ADMIN_USERNAMES", "CORS_ORIGINS", "TRUSTED_PROXIES",
]

# 推送凭据已经进库了才删。搬之前删掉它们，等于把那份钥匙扔了——它只在这个文件里。
FCM_ENV_KEYS = ["FCM_PROJECT_ID", "FCM_SERVICE_ACCOUNT_JSON"]

# CORS_ORIGINS 单独说一句：它现在是**额外**放行项，租户控制台的来源由 tenant_domain
# 表推导。删它之前必须确认那几个来源确实在表里——2026-09-13 核对过 amos 上的三个
# console.* 域名都在，所以删得掉。换一台机器之前请重新核对，别照抄这个结论。
DROP_CORS_ORIGINS_ONLY_IF_IN_TENANT_DOMAIN = True


# 值里含这些字符时，不加引号就会在 `set -a; . file` 那一刻被 shell 解释。
#
# 2026-09-13 的第二次泄漏就是这么来的：MYSQL_DSN 的值里有 tcp(...)，bash 报
# "syntax error near unexpected token '('" 并**把出错那一整行连口令一起回显**。
# systemd 的 EnvironmentFile 会剥掉引号（在 amos 上验过），所以加引号对两边都对。
SHELL_UNSAFE = set("()&$`|;<>*?#'\" \t")


def needs_quoting(value):
    return any(ch in SHELL_UNSAFE for ch in value)


def quoted(value):
    """按单引号包起来。值里自己含单引号时用 '\'' 的经典写法拼接。"""
    return "'" + value.replace("'", "'\\''") + "'"


def unsafe_lines(lines):
    """挑出未加引号、而值里含 shell 元字符的行。返回 [(行号, 键)]。"""
    bad = []
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            continue  # 已经加了引号
        if needs_quoting(value):
            bad.append((number, key))
    return bad


def read_env(path):
    """按行读，保留注释和空行的位置——把注释一起洗掉会让剩下的键失去解释。"""
    with open(path) as handle:
        return handle.read().splitlines()


def value_of(lines, key):
    prefix = key + "="
    for line in lines:
        if line.startswith(prefix):
            value = line[len(prefix):].strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            return value
    return None


def build_dsn(lines):
    """用旧的十一个键拼一条等价 DSN。

    口令原样放：驱动取第一个 ':' 到**最后一个** '@' 之间的全部内容，所以口令里的
    @ / : ( ) 都不会断。只有用户名不能含 ':'。
    """
    user = value_of(lines, "MYSQL_USER") or "root"
    if ":" in user:
        sys.exit("MYSQL_USER 里含 ':'，DSN 无法表达（驱动按第一个 ':' 切用户名）")
    password = value_of(lines, "MYSQL_PASSWORD") or ""
    host = value_of(lines, "MYSQL_HOST") or "127.0.0.1"
    port = value_of(lines, "MYSQL_PORT") or "3306"
    database = value_of(lines, "MYSQL_DATABASE")
    if not database:
        sys.exit("MYSQL_DATABASE 是空的，拒绝拼一条连不上的 DSN")

    # "Z" 是 ISO-8601 的 UTC 记号，不是时区名。驱动用 time.LoadLocation，不认它。
    zone = value_of(lines, "MYSQL_TIMEZONE") or "UTC"
    if zone == "Z":
        zone = "UTC"

    def seconds(key, fallback):
        raw = value_of(lines, key)
        return (raw if raw else fallback) + "s"

    params = {
        "parseTime": (value_of(lines, "MYSQL_PARSE_TIME") or "true"),
        "loc": zone,
        "charset": value_of(lines, "MYSQL_CHARSET") or "utf8mb4",
        "timeout": seconds("MYSQL_CONNECT_TIMEOUT_SECONDS", "15"),
        "readTimeout": seconds("MYSQL_READ_TIMEOUT_SECONDS", "30"),
        "writeTimeout": seconds("MYSQL_WRITE_TIMEOUT_SECONDS", "30"),
    }
    if params["parseTime"] != "true":
        sys.exit("MYSQL_PARSE_TIME 不是 true，而整套代码把 DATETIME 扫进 time.Time；"
                 "先弄清为什么会这样，别让这个脚本把它带进 DSN")
    query = "&".join(f"{k}={urllib.parse.quote(v, safe='')}" for k, v in params.items())
    # 一定加引号：值里必然有 tcp(...) 和 &，不加引号 source 这个文件时 bash 会报错
    # 并把整行连口令一起打出来。systemd 会剥掉引号，所以两边都对。
    return "MYSQL_DSN=" + quoted(f"{user}:{password}@tcp({host}:{port})/{database}?{query}")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--apply", action="store_true", help="真的改文件；不加就只报告")
    parser.add_argument("--fix-quoting", action="store_true",
                        help="给所有需要引号的值加上单引号，其它一概不动。"
                             "这是 --check 报出问题之后的最小修法")
    parser.add_argument("--check", action="store_true",
                        help="只检查有没有未加引号、会让 source 报错的值，然后退出。"
                             "报错会把整行连值一起回显，所以这是一条机密泄漏路径")
    parser.add_argument("--target", default=TARGET)
    parser.add_argument("--keep-cors", action="store_true",
                        help="保留 CORS_ORIGINS。控制台来源不在 tenant_domain 表里时必须加")
    parser.add_argument("--drop-fcm", action="store_true",
                        help="删掉 FCM_PROJECT_ID / FCM_SERVICE_ACCOUNT_JSON。"
                             "**先跑 `rn-server push-credentials import-env`**——"
                             "那份钥匙只存在于这个文件里，搬进库之前删掉就没了")
    args = parser.parse_args()

    lines = read_env(args.target)

    if args.fix_quoting:
        bad = unsafe_lines(lines)
        if not bad:
            print(f"{args.target}: 没有需要加引号的值，未改动。")
            return
        stamp = time.strftime("%Y%m%d-%H%M%S")
        backup = f"{args.target}.bak-{stamp}"
        shutil.copy2(args.target, backup)
        os.chmod(backup, 0o600)
        doomed = {number for number, _ in bad}
        out = []
        for number, raw in enumerate(lines, 1):
            if number in doomed:
                key, value = raw.strip().split("=", 1)
                out.append(f"{key}={quoted(value)}")
            else:
                out.append(raw)
        with open(args.target, "w") as handle:
            handle.write("\n".join(out).rstrip("\n") + "\n")
        os.chmod(args.target, 0o600)
        # 只报键名，不报值
        print(f"{args.target}: 给这些键的值加了单引号：" + ", ".join(key for _, key in bad))
        print(f"备份在 {backup}。systemd 会剥掉引号，重启服务即可。")
        return

    if args.check:
        bad = unsafe_lines(lines)
        if not bad:
            print(f"{args.target}: 所有值都可以安全地 source。")
            return
        print(f"{args.target}: 这些行的值含 shell 元字符却没加引号——")
        for number, key in bad:
            print(f"  第 {number} 行  {key}")
        print("\nsource 这个文件时 bash 会在这里报错，并把整行**连值一起**回显。")
        print("给这些值加单引号（systemd 会剥掉，不影响服务）。")
        raise SystemExit(1)

    have = {line.split("=", 1)[0] for line in lines if "=" in line and not line.startswith("#")}

    if "MYSQL_DSN" in have:
        print("MYSQL_DSN 已经在了，不重复生成。")
        dsn_line = None
    else:
        dsn_line = build_dsn(lines)

    removing = []
    for key in LEGACY_MYSQL:
        if key in have:
            removing.append((key, "合进 MYSQL_DSN"))
    for key, why in DEAD.items():
        if key in have:
            removing.append((key, why))
    for key, default in DEFAULTS.items():
        if key in have and value_of(lines, key) == default:
            removing.append((key, f"值就是默认值 {default}"))
    for key in DROP_IF_EMPTY:
        if key == "CORS_ORIGINS" and args.keep_cors:
            continue
        if key in have and value_of(lines, key) == "":
            removing.append((key, "空的"))
    if args.drop_fcm:
        for key in FCM_ENV_KEYS:
            if key in have:
                removing.append((key, "已搬进库（app_configs 的 push.fcm，tenant 0）"))

    # CORS_ORIGINS 非空时也删：租户域名由 tenant_domain 推导。但必须先核对过
    if not args.keep_cors and "CORS_ORIGINS" in have and value_of(lines, "CORS_ORIGINS"):
        removing.append(("CORS_ORIGINS", "控制台来源已在 tenant_domain 表里（2026-09-13 核对过）"))

    doomed = {key for key, _ in removing}
    kept = sorted(have - doomed)

    print(f"当前 {len(have)} 个键。")
    print(f"\n要删 {len(removing)} 个：")
    for key, why in sorted(removing):
        print(f"  - {key:<40} {why}")
    if dsn_line:
        print("\n要加 1 个：\n  + MYSQL_DSN                              （值不打印）")
    print(f"\n剩下 {len(kept) + (1 if dsn_line else 0)} 个：")
    for key in kept:
        print(f"    {key}")

    if not args.apply:
        print("\n（只是报告。确认之后加 --apply）")
        return

    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup = f"{args.target}.bak-{stamp}"
    shutil.copy2(args.target, backup)
    os.chmod(backup, 0o600)

    out = []
    for line in lines:
        key = line.split("=", 1)[0] if "=" in line and not line.startswith("#") else None
        if key in doomed:
            continue
        out.append(line)
    if dsn_line:
        # 放在文件开头附近的机密段：它是这份文件里最要紧的一行
        out.insert(0, dsn_line)
    with open(args.target, "w") as handle:
        handle.write("\n".join(out).rstrip("\n") + "\n")
    os.chmod(args.target, 0o600)
    print(f"\n改好了。备份在 {backup}")
    print("下一步：`rn-server config` 核对，然后重启服务。")


if __name__ == "__main__":
    main()
