# 在 Rancher 上跑服务端：Mac 打包机要的那几条

这份文档只回答一件事：**服务端从 amos 那台虚拟机搬到 Rancher（或任何 Kubernetes）之后，家里的
Mac 打包机还能不能装上、领到任务、把包传出去。** 与 iOS 无关的部署事项（数据库、对象存储、扫链、
控制台静态站）不在这里，看 [`../DEPLOYMENT.md`](../DEPLOYMENT.md)。

设计来源：`docs/design/ios-mac-builders-home-network-2026-09-18.md` §2.3、§8 S8、§9 阶段 E。

前提：Mac 在家里、没有公网地址、只出不进（[`../build-agent-macos/`](../build-agent-macos/)）。所以
这一侧要满足的全部是**入站方向**的事：让 Mac 发出去的请求能原样到达服务端进程，以及让服务端手里
真的有安装包可给。

## 1. 清单

按重要性排，每条都写了「不配会怎样」——这几个故障的症状都不指向原因。

| # | 要做什么 | 不配会怎样 |
| --- | --- | --- |
| 1 | 安装包目录挂成卷（见 §2） | 新 Mac 执行装机命令，第一步 `describe` 就回 503 `MACHINE_BUNDLE_UNAVAILABLE`；已经在跑的机器自升级也拿不到 |
| 2 | `TRUSTED_PROXIES` 填 Ingress 的 Pod 网段（见 §3） | 所有 Mac 的注册请求在服务端看来来自同一个 IP，20 次/分钟的限速被它们共用；同时装两三台就会互相打满 |
| 3 | `/v1/build-agent/*` 与 `/v1/machine-setup/*` 直接 200，不重定向（见 §4） | 代理拒绝一切 3xx，报「refusing redirect」后退出；日志里看不出是 Ingress 加的跳转 |
| 4 | 别给这两组路径配请求头白名单 | `x-machine-token` / `x-build-attempt` / `x-enrollment-code` 被剥掉 → 401，看起来像令牌坏了 |
| 5 | `proxy-read-timeout` ≥ 60 秒 | 长一点的认领轮询被中断，任务看起来一直没人领 |
| 6 | `proxy-body-size` ≥ 2 GiB（**这条是 Android 的**） | Android 的未签名包 PUT 被 413。iOS 任务不上传产物，最大的请求体是 `logTail` |
| 7 | NetworkPolicy 放行出站到 `api.appstoreconnect.apple.com:443` | 模式 A 的 TestFlight 只读同步失败；打包与上传不受影响（上传发生在 Mac 上） |
| 8 | 多副本可以直接开（见 §5） | — |

**不需要做的**：给 Mac 的出口 IP 加白名单（家用宽带的地址会变，做不到也不该依赖）；给服务端加 mTLS
（令牌 + TLS 已经够，而证书轮换会变成每台 Mac 的运维负担）；打 VPN。运维要远程维护 Mac 可以自己用
Tailscale 或屏幕共享，那与打包链路无关。

## 2. 安装包目录

服务端从 **`/opt/rn-foundation/machine-bundles/current`** 读安装包。这是**部署约定，不是配置项**：
env 里没有对应的键，改不了路径（`internal/api/machine_setup.go` 的 `defaultMachineBundleDir`）。

目录里要有：

```
manifest.json                  # 提交 + 每个归档与每个文件的 sha256
manifest.sig                   # 清单的离线签名（见下）
signer.tar.gz                  # 签名闸
builder.tar.gz                 # linux/amd64 构建机
builder-darwin-arm64.tar.gz    # Mac 打包机
```

在 amos 上这些由 `rn-foundation-apply bundles <提交>` 原子切换 `current` 软链放好。Rancher 上有两种做法：

- **挂卷（推荐）**：`deploy/setup/build-bundles.sh` 在 CI 里跑，产物推进一个 PVC 或对象存储同步下来的
  目录，挂到 `/opt/rn-foundation/machine-bundles/current`。**只读挂载**就够——服务端只读它。
- **打进镜像**：`COPY` 到那个路径。代价是换一次安装包要重新发一版服务端，而这两件事的节奏不一样。

**`manifest.sig` 必须一起放。** 它不是可选的：`GET /v1/build-agent/bundle`（Mac 自升级的下载口）在
清单没有签名、签名与清单对不上、或者提交带 `-dirty` 时一律回 503，什么都不给。签名由平台管理员在离线
机器上用 `signing/cmd/bundle-sign` 生成——服务端手里没有那把私钥，这正是"服务端被攻破也换不出一个能
过验的清单"的全部依据。

装机用的 `POST /v1/machine-setup/describe` 与 `GET /v1/machine-setup/bundle/:archive` 不看签名（那时
机器还没有任何信任根，核对靠运维手上的三个带外 sha256）；自升级那条路看。

怎么确认：

```bash
kubectl -n <ns> exec deploy/rn-foundation-server -- ls -l /opt/rn-foundation/machine-bundles/current
curl -fsS "$API/v1/build-agent/bundle?os=darwin&arch=arm64" | jq '{commit, signature: .signature.sequence}'
```

第二条要带一个有效的机器令牌（`-H "x-machine-token: rnm_…"`）。回 503 时响应里写着缺哪一样。

## 3. `TRUSTED_PROXIES`

```yaml
env:
  - name: TRUSTED_PROXIES
    value: "10.42.0.0/16"   # 换成本集群 Ingress 控制器所在的 Pod 网段
```

它决定 `ClientIP()` 取直连对端还是 `X-Forwarded-For`。三条装机接口（`describe`、`bundle`、`enroll`）
各自按来源 IP 每分钟 20 次限速，计数放在**进程内存**里。

空着 = 谁都不信，所有请求的 `ClientIP` 都是 Ingress 的 Pod IP：限速从"每台机器 20 次"变成"整个集群
20 次"。装一台 Mac 正常要敲十几次（重试、重跑同一条命令），两个人同时装就会互相踩。

反过来，填一个比实际更宽的网段等于让任何能设 `X-Forwarded-For` 的人随便换 IP，限速就成了摆设。
填 Ingress 控制器实际所在的网段，不要填 `0.0.0.0/0`。

`externalOrigin`（拼进安装命令的那个地址）与这个键**无关**：`Environment=production` 下它恒为 https。

## 4. Ingress

```yaml
metadata:
  annotations:
    nginx.ingress.kubernetes.io/proxy-read-timeout: "120"
    nginx.ingress.kubernetes.io/proxy-body-size: "2g"
```

要避开的是**跳转**。`cmd/build-agent/client.go` 的 `refuseRedirects` 让代理拒绝一切 3xx——跟随重定向
会把机器令牌带到另一个地址去，所以它宁可失败。`ssl-redirect` 对 https 直连没有影响（Mac 只走 https），
但下面这些要检查：

- 尾斜杠规范化、`www` 前缀跳转、大小写路径重写：这些路径上都不要做。
- 多个 Ingress 规则命中同一路径时的兜底跳转。
- 服务网格（Istio / Linkerd）的重试与重定向策略。

请求头**默认透传**就是对的，只要别配白名单。要配的话至少放行 `x-machine-token`、`x-build-attempt`、
`x-enrollment-code`。

## 5. 多副本

直接开，不需要选主：

- **认领**走 MySQL 命名锁 + `FOR UPDATE … SKIP LOCKED`（`internal/api/build_agent.go` 的 `claimBuildJob`），
  两个副本同时收到两台 Mac 的认领，各拿到一条不同的任务。
- **回收器**（`build_reaper.go`）按 `attempt` 守护：每个副本各跑一轮是幂等的，同一条任务不会被回收两次。
- **排队超 6 小时的告警**靠审计去重，每条任务只发一次，与副本数无关。

**限速是按副本各算的**（计数在进程内存里）。N 个副本 = 实际上限 N × 20 次/分钟，且同一台 Mac 的连续
请求可能落在不同副本上。这不是 bug，是这个实现的事实：那道限速防的是"有人拿注册码撞库"，不是精确配额。
要精确，得把计数挪到 Redis 或 Ingress 上——现在没有这个需求，写在这里是免得有人按"20 次"去算容量。

## 6. 怎么确认成功（设计 §9 阶段 E）

1. `describe` 能从卷里读到安装包：在一台 Mac 上跑装机命令的第一步，不报 503。
2. 控制台给出的安装命令里是 **https 的外部域名**，不是集群内地址或 http。
3. 两个副本同时在，两台 Mac 同时认领：各拿到一条任务，没有一条被领两次
   （`SELECT id, claimed_by, attempt FROM build_jobs WHERE status IN ('claimed','running')`）。
4. 一台 Mac 的自升级能走通：`GET /v1/build-agent/bundle` 回 200 且带签名，Mac 上
   `/var/rn-build-agent/state/upgrade-failed.json` 不出现。
5. 拔掉那台 Mac 的网线 15 分钟再插回：任务被回收重排，控制台上那台标「离线」，恢复后自己回来。
