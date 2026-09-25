# API 反代的公共部分。被 conf.d/rn-foundation.conf 里每个 api.* 的 server 块 include。
# 抽出来是因为域名按证书分组，一个 zone 一个 server 块，body 完全一样。
# 转发本身（上传上限、超时、转发头）在 rn-foundation-snippet-api-proxy.inc，控制台的 /v1/ 也用它。

location / {
    include /etc/nginx/conf.d/rn-foundation-snippet-api-proxy.inc;
}
