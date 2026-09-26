# API 反代的公共部分。被 conf.d/rn-foundation.conf 里每个 api.* 的 server 块 include。
# 抽出来是因为域名按证书分组，一个 zone 一个 server 块，body 完全一样。
# 转发本身（上传上限、超时、转发头）在 rn-foundation-snippet-api-proxy.inc，控制台的 /v1/ 也用它。

# 统一登录只能从控制台域名发起、回到控制台域名：从 api.* 发起的话，发起时的临时 Cookie 落在 api.* 上，
# 回调（在 console.*）永远对不上；回调地址也只在认证中心登记了 console.*。直接在 api.* 上关掉，免得有人误用
location = /v1/admin/auth/cid/start {
    return 404;
}
location = /client/v1/oauth/login {
    return 404;
}

location / {
    include /etc/nginx/conf.d/rn-foundation-snippet-api-proxy.inc;
}
