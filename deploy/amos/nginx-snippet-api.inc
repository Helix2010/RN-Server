# API 反代的公共部分。被 conf.d/rn-foundation.conf 里每个 api.* 的 server 块 include。
# 抽出来是因为域名按证书分组，一个 zone 一个 server 块，body 完全一样。
# 转发本身（上传上限、超时、转发头）在 rn-foundation-snippet-api-proxy.inc，控制台的 /v1/ 也用它。
# 按路径分给 App 端与平台端（RN-Server 设计 service-and-console-split-2026-09-27 §3.4）。

# 打包机、签名闸与新机器注册归平台端。机器配置的地址仍是 https://api.*，按路径转过去，不用改任何一台机器
location ^~ /v1/build-agent/ {
    set $rn_service rn_platform;
    include /etc/nginx/conf.d/rn-foundation-snippet-api-proxy.inc;
}
location ^~ /v1/signer/ {
    set $rn_service rn_platform;
    include /etc/nginx/conf.d/rn-foundation-snippet-api-proxy.inc;
}
location ^~ /v1/machine-setup/ {
    set $rn_service rn_platform;
    include /etc/nginx/conf.d/rn-foundation-snippet-api-proxy.inc;
}

# 其余归 App 端。App 端没有 /v1/admin，也没有统一登录的发起与回调，从 api.* 访问都是 404：
# 管理接口只能从控制台域名（或本机直连租户端、平台端的端口）调
location / {
    set $rn_service rn_app;
    include /etc/nginx/conf.d/rn-foundation-snippet-api-proxy.inc;
}
