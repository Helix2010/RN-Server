# 设计：单台打包机上的构建并发与队列公平

状态：Revised Draft（2026-09-15，经三路对抗性评审后重写）。修订 `docs/design/build-service-2026-09-11.md` §「并发」在单机场景下的落地方式，不改动该文档确立的安全论证（服务端不下发命令、签名密钥只加密给打包机、任务不自动重排）。

初稿提出「一个安装包实例 + 一个热更新实例」的两通道方案。**评审后撤回**，理由见 §7。本稿的主张是：先装仪器、先修真 bug、测两周，再决定要不要优化队列——如果要，走一行 SQL，不是两个进程。

## 1. 现状

### 1.1 今天不会发生资源争抢

打包机代理是单线程循环（`cmd/build-agent/main.go:77-101`）：`pollOnce` 领一条任务、从头做到尾、才回来领下一条，没有 worker 池。服务端发任务是 `FOR UPDATE SKIP LOCKED` + 事务（`internal/api/build_jobs.go:684-740`），一次只发一条。

所以「多租户并发提交 → 打包机资源争抢 → 构建失败」这条链断在第一环：同一时刻机器上只有一个构建。amos 的余量也远未触及（16 核 / 62 GiB / 449 GB 可用，Gradle 单进程 `-Xmx4096m`，共享 Gradle 缓存 6.3 GB）。

### 1.2 队列耦合是真的，但量级远比初稿说的小

队列是一条，跨租户，纯 FIFO（`build_jobs.go:696-697`）。热更新和安装包共用它，所以热更新会排在安装包后面。

**初稿在这里写了「二十分钟的安装包构建」，这个数没有依据，已删除。** 仓库里关于构建时长的三个数：

| 数 | 出处 | 条件 |
|---|---|---|
| 约三分钟 | `docs/design/build-service-2026-09-11.md:118` | 设计时的估计 |
| **六分钟** | `internal/api/build_jobs.go:317`，标注 `2026-09-12 实测` | **打包机上真实跑的那一条** |
| 21m08s | `RN-App/docs/changes/2026-09-10-feature-release-signing-gates.md:96` | GitHub 托管 runner，**冷缓存**；该作业 2026-09-12 已删除（`RN-App/.github/workflows/app-quality.yml:35-46` 是它的墓碑注释） |

以打包机上的**六分钟**为准。热更新的时长**没有任何实测**——这正是 §3 要先补的东西。

两条路径的前半段还完全相同（`git fetch` + `worktree add` + 写身份文件 + 取图标 + `pnpm install --frozen-lockfile`，`cmd/build-agent/ota.go:26` 调的就是 APK 那条用的同一个 `prepareWorktree`），所以能省掉的只是安装包独有的尾巴（prebuild + gradle + syft），不是那六分钟的全部。

### 1.3 规模

`RN-Admin/deploy/tenants.txt` 有三个租户；`RN-App/tenants/` 下只有 `anyfun` 一个目录。租户目录由服务端下发合成（`cmd/build-agent/tenantfile.go:54-56` 会 `MkdirAll`），所以仓库里没有目录不等于不能构建，但**图标必须齐**（`build.go:158-162`），而 `docs/design/env-config-slimdown-2026-09-13.md:78` 记录 2026-09-13 只读查生产库时四个租户里有两个「还没有任何打包配置」。

即：今天真正会排队的租户是**一到三个**，不是十个。队列拥塞要发生，得有人在一个六分钟的构建跑到一半时再排一条。

### 1.4 单并发这个不变量服务端不知道（真问题，与队列无关）

服务端对「这台机器上同时跑几个构建」零约束。单并发完全由代理进程的串行循环维持，而 systemd 单元里没有任何防多实例的机制（无 lock 文件、无 `ConditionPathExists`）。

起第二个进程的后果不是慢，是数据损坏：两个代理共用 `GRADLE_USER_HOME`（`deploy/build-agent/rn-build-agent.service:41`，正是 build-service 文档判定为并发不安全的那个目录），而且第二个进程启动时 `pruneOrphanWorktrees` 会把 workspace 下**所有**目录删掉（`cmd/build-agent/workspace.go:22-24` 明确假设「这个 workspace 只有这一个代理在用」），包括第一个代理正在用的检出和里面那份解开的 keystore。

**这条今天就敞着，和队列优化没有任何依赖关系。**

### 1.5 认领之后的失败路径会留下僵尸任务

`tx.Commit()` 在 `build_jobs.go:740`，之后这些分支直接 5xx 返回，**没有**调 `markBuildJobFailed`：

| 行 | 分支 |
|---|---|
| `:750-754` | `buildConfigFor` 失败 → 500 `BUILD_CONFIG_INVALID` |
| `:761-765` | `buildIconsForJob` 失败 → 500 `BUILD_ICONS_INVALID` |
| `:770-780` | `tenantManifestFor` 非 `missingIdentity` 错 → 500 `APP_IDENTITY_INVALID` |
| `:784-788` | `otaSigningRecord` 失败 → 500 `OTA_SIGNING_CONFIG_INVALID` |
| `:817-821` | `sealedBuildKeystoreFor` 失败 → 500 `BUILD_KEYSTORE_CONFIG_INVALID` |

`:774`（身份缺失）和 `:805`（OTA 基线失效）已经做对了，照抄即可。今天的代价是「列表里一条僵尸 + 占一个 build 号」，10 分钟后被看门狗回收。

### 1.6 卡死回收依赖有人在轮询

10 分钟无心跳判失败的回收逻辑只在 claim 路径上被调用（`build_jobs.go:682` 是生产代码里的唯一调用点，`cmd/server` 里没有定时器）。所有代理都挂掉时回收永远不发生。

另外 `reapStaleBuildJobs` 的 WHERE 是 `status IN ('claimed','running')`（`:910`）——**`queued` 永远不回收**。而 `createBuildJob` 接受 `platform: ios`（`:288`），没有任何代理会领它（`BUILD_AGENT_PLATFORMS` 默认 android），于是一条 ios 安装包任务会永远 `queued`。OTA 那条路径已经在排队时就拒了（`build_ota_jobs.go:83-87`），APK 没有对应的闸。

## 2. 目标与非目标

**目标**

1. 误起第二个代理实例不造成数据损坏。
2. 认领之后的失败路径不留僵尸任务。
3. 卡死任务在所有代理都挂掉时也能回收。
4. **让队列等待时间可观测**——在决定是否优化它之前。

**非目标**

- 不做两通道（撤回，见 §7）。
- 不做多台打包机（见 §8）。
- 不提高单次构建速度（见 §9）。
- 不做 iOS 构建。

## 3. 方案

按「独立收益、互不依赖、可单独回滚」排序。前四条都不需要迁移、不需要改部署拓扑。

### 3.1 代理 workspace 独占锁

代理启动时对 `BUILD_AGENT_WORKSPACE` 取 `flock`（非阻塞），拿不到就打日志退出。

锁必须在 `os.MkdirAll(cfg.Workspace, …)`（`main.go:31`）**之后**、`pruneOrphanWorktrees`（`main.go:55`）**之前**取，否则删除已经发生了。

**它只防配错，不防恶意**——任何能以 `builder` 身份起进程的人都可以不去取锁。目标 1 的措辞（「误起第二个代理实例」）是准确的，保持它。

**它也只盖住五个共享资源中的一个。** `pruneOrphanWorktrees` 还会对 `cfg.Repo` 跑 `git worktree remove --force` 和 `git worktree prune`（`workspace.go:42`、`:55`），workspace 上的锁对裸库一无所知；`GRADLE_USER_HOME`、pnpm store 同理。所以除了 flock，启动时还要**断言 (Workspace, StateDir, Repo, GRADLE_USER_HOME, pnpm store) 两两不重叠**，重叠即拒绝启动。

特别注意 `StateDir` 是**推导**出来的，不是配置的：`cfg.StateDir = filepath.Dir(cfg.Workspace)`（`cmd/build-agent/config.go:89-92`）。把 workspace 改成同级的另一个目录，StateDir 会悄悄指向同一个地方，也就是同一把 `agent-key`。

flock 的边角行为核实过：锁挂在 open file description 上，进程死亡（含 SIGKILL、OOM）由内核释放，**不存在崩溃后的残留锁**，所以长不出 `rm -f` 那种运维土办法。Go 的 `os.Open` 默认带 `O_CLOEXEC`，`run()` 拉起的 gradle/pnpm 不会继承锁 fd——这一条是「没有残留锁」成立的唯一实现细节，改动 `run()` 时要记得。

### 3.2 认领之后的失败路径要判失败

§1.5 那五条分支全部改成先 `s.markBuildJobFailed(ctx, job.ID, <具体原因>)` 再 `problem(...)`。

**这一条必须排在 §3.5 的在途闸之前**：那些分支最典型的触发原因（`BUILD_CONFIG_INVALID`、`BUILD_KEYSTORE_CONFIG_INVALID`）恰恰是「运维去控制台改两下配置然后重排」，而在途闸会让重排吃 409——修复动作被自己的故障挡住。

### 3.3 看门狗独立节拍，并把 claimed 和 running 分开判

`reapStaleBuildJobs` 从 claim 路径里摘出来，在 `cmd/server` 起一个 ticker 周期调用（1 分钟）。现成模式抄 `cmd/server/main.go:88` 的 `go dispatcher.Run(workerCtx)`。

判据分两档。代理每 30 秒心跳一次（`main.go:131`），一条 `claimed` 超过 2 分钟一次心跳都没有，只可能是它根本没收到领取响应：

```sql
WHERE (status='running' AND COALESCE(heartbeat_at, claimed_at, created_at) < ? /* now-10m */)
   OR (status='claimed' AND claimed_at < ?                                     /* now-2m  */)
```

回收动作不变：只判失败，**不重排**。`build-service-2026-09-11.md:106` 记录过这个决定——自动重排会在代理其实还活着的时候产生两个同号的包。

多实例 ticker 的竞争已核实**无害**：`markBuildJobFailed`（`:944-954`）是单条带状态守卫的 UPDATE，第二个实例 `affected=0`；而且部署本来就是单实例。

### 3.4 管理端：排队时长列

打包任务列表增加**排队时长**一列（`createdAt` → `claimedAt`，未认领的按「到现在」）。数据现成，`formatDuration` 和 1 秒 ticker 已经在「耗时」列里了（2026-09-15 上线），照着 `buildElapsedMs` 再写一个 `queueWaitMs` 即可。零服务端改动、零迁移。

「耗时」列刻意只算从认领到结束、不含排队，理由是把两者混成一个数会让「机器慢」和「队伍长」无法区分。要判断队列到底堵不堵，就需要这个数单独可见。

**这是本方案里唯一能回答「§3.5 和 §3.6 值不值得做」的仪器，所以它排在它们前面。** 先量再改。

### 3.5 安装包的按租户在途闸（测量之后再决定）

热更新已经有这道闸（`live_ota_slot`，`internal/store/migrations.go:1503-1518`），安装包没有。迁移 45 的注释认为「APK 那边的并发上限是 build 号递增天然给的」（`:1459-1461`），这个推论不成立：递增只约束号的取值，不约束在途条数。

补上之后，队列上限就等于租户数——「一个租户连排十条」在算术上不可能发生。

**但这条迁移有一个能让整个后端下线的失败模式，必须按 §5 的顺序做。**

#### 3.5.1 复用映射表

| 拟新增 | 结论 | 理由 |
|---|---|---|
| 打包机登记表（`build_agents`） | **取消** | 单机不需要区分机器。`build-service-2026-09-11.md:39` 已记录过取消这张表的决定。 |
| 队列配额表 | **取消** | 配额是一个常量，用生成列 + 唯一索引表达。 |
| `build_jobs.live_apk_slot` 生成列 + 唯一索引 | **新建列** | 与 `live_ota_slot` 同构；换成应用层计数会引入 TOCTOU。 |
| `ix_build_jobs_queue_kind` 索引 | **新建索引** | claim 加 kind 过滤后需要，见 §3.6。只在做 §3.6 时才建。 |

不新增表。

#### 3.5.2 迁移 47

**必须写成幂等的**，照抄迁移 45 的手法（`addColumnIfMissing` 加列 + 查 `information_schema.STATISTICS` 再建索引，模板在 `migrations.go:1503-1518`）。**不要抄下面这段裸 DDL 进代码**——它只是说明语义：

```sql
ALTER TABLE build_jobs ADD COLUMN live_apk_slot TINYINT UNSIGNED
  GENERATED ALWAYS AS (
    CASE WHEN kind='apk' AND platform='android'
              AND status IN ('queued','claimed','running') THEN 1 ELSE NULL END
  ) STORED
  COMMENT '未结束的安卓安装包任务占位。取值：1=这条是还没结束的安卓安装包任务；NULL=已结束（succeeded/failed/canceled）、不是安装包任务、或不是安卓。唯一索引建在它上面，限制同租户同时只能有一条在途安卓安装包任务；MySQL 唯一索引不比较 NULL，所以任务结束后可以立刻排下一条。由数据库生成，无人写入';

CREATE UNIQUE INDEX ux_build_jobs_live_apk ON build_jobs (tenant_id, platform, live_apk_slot);
```

与初稿的差别：**生成列里多了 `platform='android'`**。理由见 §1.6——一条 ios 安装包任务会永远 `queued` 且永远不被回收，会把这个租户的闸**永久**占住。更彻底的修法是排队时就拒 ios 安装包（与 OTA 对称，`build_ota_jobs.go:83-87`），两条建议一起做；生成列里这个条件是第二道保险。

实测要点（MySQL 8.0.46）：

- 加 STORED 生成列**只能 `ALGORITHM=COPY`**（INPLACE/INSTANT 都报 ERROR 1845），即整表重建、期间阻塞 DML。`build_jobs` 很小，几百毫秒；但迁移是独立的 oneshot unit（`deploy/amos/rn-foundation-migrate.service`），跑的时候代理可能正在发心跳，心跳会短暂阻塞。写进迁移注释。
- STORED 生成列在状态流转时会重算并更新唯一索引。实测三种转换：`claimed→running`（slot 仍是 1）并发 INSERT **立即** 1062 报错不等锁；`→succeeded`/`→failed`（slot 1→NULL）并发 INSERT 等到那个事务结束，而这四个写入点全是 autocommit 单语句（`:882`、`:981`、`:949`、`:620`），微秒级。**没有构成死锁环的加锁顺序差异**，这条风险可以划掉。
- `COMMENT` 里不能出现单引号，`migrations.go` 的集成测试在这上面挡过一次。

#### 3.5.3 唯一键冲突要翻成 409

安装包排队现在把任何 INSERT 错误都返回 500 `BUILD_JOB_SAVE_FAILED`（`build_jobs.go:390-396`）。热更新那边已经做对了（`build_ota_jobs.go:143-147`）。

- 命中 `ux_build_jobs_live_apk` → 409 `APK_BUILD_ALREADY_QUEUED`。**文案必须带上占着闸的那条任务 id 和它的状态**，否则运维会去列表里找，找到一条 `running` 然后发现取消不了（见 §3.5.4），这一步没有出口。
- 命中 `ux_build_jobs_live_build_number` → 409 `BUILD_NUMBER_IN_USE`。这条今天也会掉进 500：floor 检查在事务外（`:301` 读，事务 `:384` 才开），并发同号提交的第二条靠唯一索引兜住，但错误被翻成 500，控制台显示「排队失败」，人会重试。

实测：一条同时违反两个唯一索引的 INSERT，MySQL 报的是**先建的那个索引**（`ux_build_jobs_live_build_number`，迁移 45 早于 47）。所以两个 `strings.Contains` 分支都要有，**不能假设哪个先命中**。

#### 3.5.4 必须一起做：给 `running` 一条逃生口

`cancelBuildJob` 只放行 `status IN ('queued','claimed')`（`:621`），`running` 打不进去（注释的理由是对的：取消了也停不下打包机上那个进程，状态会骗人）。

在途闸把这变成了租户级冻结，而触发方式写在我们自己的运维注释里：unit 明写「急着换就 `systemctl kill -s SIGKILL rn-build-agent`」（`rn-build-agent.service:30-32`）→ 进程没了、不再心跳、也没有上报 → 任务停在 `running` → 取消返回 409 → **这个租户 10 分钟排不了安装包，无解**。

所以在途闸上线的同时，管理端要有一条**强制判失败**（带 reason + 二次确认，走 `markBuildJobFailed`）。「不自动重排」的决定不等于「不能手动收尾」。

（评审曾提出「取消一条 `claimed` 任务会让租户被锁」，核实**不成立**：cancel 把状态直接置 `canceled`，生成列随即变 NULL，闸门当场释放。）

### 3.6 如果测出来队列真的堵：一行 SQL

不要起第二个进程。认领语句是一行（`build_jobs.go:697`），改排序让热更新优先：

```sql
ORDER BY (kind='ota') DESC, created_at
```

显式写 `(kind='ota') DESC` 而不是靠 `kind` 的枚举序号，是为了不被将来新增的枚举值坑到。

饿死风险有界：`live_ota_slot` 已经把热更新限成「同租户同平台同时一条」，租户数就是能插队的条数上限，安装包最多多等一轮热更新。

**代价对比**：这条是 1 行 + 1 个测试，没有新进程、新用户、新目录、新迁移、新升级顺序耦合。它拿不到的只是「热更新到达时安装包已经在跑」那段重叠——按六分钟构建和当前频次算，期望值是秒级。

不要加 `priority` 列：`kind` 已经是优先级信号，再加一列违反 `AGENTS.md:102`「一个事实只有一个存放处」。

## 4. 本次不做，且要说明为什么

**每代理在途上限**。服务端不看认领者手上已有几条任务。单机单实例下这条买不到什么，而误起的第二个实例已经被 §3.1 挡住。多机时它变成必需，见 §8。

**上报绑定 `claimed_by`**。初稿提议给 heartbeat / complete / fail 的 WHERE 加 `AND claimed_by=?`。撤回：它防的是两个本地实例互相打架，而两通道已经撤回了；而且它引入一个真实的新脆弱性——每次构建的成败会取决于一个自报字符串在两次请求间保持一致（改主机名、构建中途重启、`BUILD_AGENT_NAME` 带尾空格，都会让所有上报变成 409，10 分钟后被看门狗判失败）。将来真要做，必须：`agent` 为空时**跳过**绑定检查（见 §5 的升级顺序陷阱）、上报用的名字从 **claim 响应里回显的那个**取而不是从本地配置再读一次、以及用与 claim 完全相同的 `clipRunes(TrimSpace(...), 120)` 规范化。

顺带记录两处现状，本次不改：`heartbeat`、`fail` 两条路由没包 `buildAgentJobScope`（`internal/api/server.go:211`、`:214`），补上会把「id 不存在」的响应从 409 变成 404，契约有变化；`markBuildJobFailed` 的 WHERE 写着 `status IN ('pending','claimed','running')`（`:950`），而枚举里**没有 `pending`** 这个值，今天无害但会误导读代码的人。

## 5. 落地顺序与回滚

### 阶段 0：只读体检（不部署任何东西）

只有要做 §3.5 时才需要。在 amos 生产库上跑：

```sql
SELECT tenant_id, platform, COUNT(*) n, GROUP_CONCAT(id) FROM build_jobs
 WHERE kind='apk' AND platform='android' AND status IN ('queued','claimed','running')
 GROUP BY tenant_id, platform HAVING n > 1;
```

**非空就绝对不能部署。** 实测后果（MySQL 8.0.46，逐字执行 §3.5.2 的 SQL）：

```
ADD COLUMN           → 成功，列落盘
CREATE UNIQUE INDEX  → ERROR 1062: Duplicate entry '1--1'
重跑同一份 SQL       → ERROR 1060: Duplicate column name 'live_apk_slot'
```

而迁移失败 → `Migrate` 返回 error（`internal/store/migrations.go:988-990`）→ `schema_migrations` **不记 47** → `store.Open` 返回 error → 进程退出；`MYSQL_AUTO_MIGRATE` 默认 true（`internal/config/config.go:137`）。下次启动重跑 47，列已存在、索引再撞一次。**永久启动失败循环，整个 wallet 后端下线**，不只是打包功能。恢复只能人工连库改数据。

CI 抓不到这个：开发库里 `build_jobs` 只有一条 `succeeded`。**它只在 amos 上炸。**

索引创建失败要给可操作的错误，把冲突的 `(tenant_id, platform)` 列进 error 里——否则运维看到的是一句 `Duplicate entry '1--1'`。

### 阶段 1：无迁移、无部署拓扑变化

1. §3.2 认领后的失败路径判失败（纯服务端，独立收益）
2. §3.3 看门狗 ticker + claimed 的 2 分钟短判据（纯服务端）
3. §3.4 排队时长列（纯管理端）
4. §3.1 flock + 目录不重叠断言（纯代理）

四条互不依赖，可以各自单独上、单独回滚。**如果只做一件，做 §3.1**——它防的损害是不可逆的（明文 keystore + 被删掉的检出），且今天就存在。**如果只做一件针对队列的，做 §3.4**——没有它无法判断后面两条值不值。

### 阶段 2：测两周

看热更新的 p95 排队时长。不痛就停在这里。

### 阶段 3：只有测出来痛才做

先 §3.6 的一行 SQL。若还不够，再评估 §3.5 的在途闸（连同 §3.5.4 的逃生口和阶段 0 的体检）。

### 回滚

- **阶段 1 的四条**：各自 revert 即可，无数据库状态。
- **§3.5 的迁移无法自动回滚。** 这个仓库没有 down migration（`AGENTS.md:26`：迁移只能向前新增），跑过的版本记在 `schema_migrations` 账本里。真要退，是手工 `DROP INDEX ux_build_jobs_live_apk` + `DROP COLUMN live_apk_slot` + **`DELETE FROM schema_migrations WHERE version=47`**，或者写迁移 48。漏掉账本那一行的后果是：服务端认为 47 已跑过、永远不再补，而排队路径开始报 unknown column。
- **只回滚代码、不 drop 索引**会让约束继续生效，而老代码不认识这个键名 → 撞闸的排队返回 500，正是 §3.5.3 要消灭的症状在一条常态触发的约束上复活。**代码回滚前先 drop 索引。**
- `live_apk_slot` 是 STORED 生成列，不携带独立数据，drop 不会丢任何行，也不影响已排队的任务。

### 升级顺序的一条陷阱（本次不涉及，但写下来）

`build-service-2026-09-11.md` 的「先服务端后代理」来自请求体的 `DisallowUnknownFields`。但**「省略」的语义在不同字段上方向相反**：

- `kinds` 是**领取条件**，省略 = 不过滤 = 与今天一致。服务端可以先上。
- `agent` 是**匹配条件**，省略 ≠ 不匹配，而是匹配空串 = 一条都不匹配。服务端先上会让所有旧代理的上报变成 409。

初稿把两者当成同一件事处理，是错的。将来加任何「匹配类」字段，服务端侧必须显式写成「空则跳过该条件」，并把这句话写进代码注释而不是只写在设计文档里。

反方向也要记：**服务端回滚时若代理已经开始发新字段**，老服务端会直接 400，代理把 400 判为不可重试（`client.go:110-115`），`pollOnce` 只 `slog.Warn` 就返回——**构建全部静默停止，管理端上看不出任何异常**。回滚必须先回代理，再回服务端。

## 6. 测试

阶段 1：

- flock：同一 workspace 起第二个进程 → 非零退出，且**断言已有的检出目录还在**（不能只断言退出码）。
- 目录重叠断言：workspace 设成与 StateDir 推导值冲突的路径 → 启动失败。
- 认领后失败路径：mock 五个分支各失败一次，断言任务落到 `failed` 且带具体原因。
- 看门狗：没有任何 claim 发生时，`running` 超 10 分钟、`claimed` 超 2 分钟分别被判失败；`claimed` 未满 2 分钟不被误判。

阶段 3（做了才需要）：

- 在途闸：同租户同平台排第二条安卓安装包 → 409 且文案里有前一条的 id 和状态；第一条转 `failed`/`canceled`/`succeeded` 之后可以再排；不同租户互不影响；ios 不受影响；热更新不受影响。
- 错误码要拆成两个用例：**不同 build 号同在途** → `APK_BUILD_ALREADY_QUEUED`；**同号但上一条已 `succeeded`**（slot 已释放、live_build_number 仍占）→ `BUILD_NUMBER_IN_USE`。不要写「并发同号提交」那个用例，它命中哪个索引取决于索引创建顺序。
- 强制判失败：`running` 任务经二次确认后落 `failed`，闸门释放。
- 优先级排序：队列里有 apk + ota 时先发 ota；只有 apk 时行为不变。

门禁（`AGENTS.md:113-116`）：

```bash
test -z "$(gofmt -l cmd internal)"
go vet ./...
go test -race ./...
go build ./cmd/server ./cmd/build-agent
```

动了迁移还要补：阶段 0 的体检 SQL 在生产库上跑过一次、以及回滚演练（drop index + drop column + 删账本行 + 老代码启动成功）。

## 7. 已撤回：一台机器上跑两条通道

初稿提议「一个安装包实例 + 一个热更新实例」跑在同一台 amos 上，各领各的。三路对抗性评审之后撤回。记在这里是为了让下一个想到这个主意的人不用再走一遍。

**收益是秒级的。** 初稿的 20:5 画像基于一个错误的构建时长（§1.2）。按实测六分钟、当前频次和一到三个租户算，安装包的占空比约 1%，每条热更新期望省下的等待是**秒**，最坏情况省六分钟——而那要求两个人在同一个六分钟窗口里各按一次按钮。

**共用 pnpm store 是从热更新实例到安装包构建的代码注入通道。** 初稿 §7 的表格写着「pnpm store 共用安全，内容寻址且自带锁」，**这是错的**。pnpm 用**硬链接**把 store 条目接进 `node_modules`（实测 RN-App 本机：`node_modules/.pnpm/is-callable@1.2.7/.../index.js` 的 `nlink=47`、`mode=664`），store 里那个文件和构建时执行的那个文件**是同一个 inode**。热更新实例能执行仓库代码（metro 在进程内求值 `app.config.ts` 与 `plugins/*.js`），于是它可以在安装包实例 `pnpm install --frozen-lockfile` 校验完、建好链接之后改写那个 inode，随后 `pnpm android:release` 会以 `builder` 身份执行被改过的 JS——而那个进程的环境里带着 `ANDROID_RELEASE_STORE_PASSWORD`，worktree 里躺着解开的 `.build-keystore.jks`。内容寻址挡不住：哈希命名的是「加入 store 那一刻的内容」，链接之后没有任何一方再读一次，这是教科书式的 TOCTOU；store 的锁是并发锁，不是访问控制。

（顺带纠正初稿的一处机理错误：RN-App 用 pnpm 10.28.1，**默认阻止依赖的生命周期脚本**，仓库里也没有 `onlyBuiltDependencies`。所以任意代码路径不是 postinstall，是 metro 求值 `app.config.ts`。机理写对很重要，否则将来有人以为配一下 pnpm 就解决了。）

**热更新实例会把每个租户的密钥校验状态翻成失败，而那个状态直接拦住安装包排队。** `verifyPendingKeystores` 在代理空闲的每一轮都跑（`main.go:84-91`，`if worked { continue }` 跳过它——而热更新通道大部分时间都空闲）。`GET /v1/build-agent/keystore-checks` 既不按任务也不按租户作用域，对任何持令牌者返回各租户的 sealed keystore（`internal/api/build_keystore_check.go:94-129`）；热更新实例用自己那把私钥必然打不开，报回 `ok=false`；`reportKeystoreCheck` 无条件覆盖该租户的共享行（`:163-169`）；然后 `createBuildJob` 直接拒绝该租户的安装包排队（`build_jobs.go:332-345` 的 `BUILD_KEYSTORE_UNUSABLE`）。两个实例还会来回抖。最危险的是人这一侧：控制台会长期显示「打包机打不开这个租户的签名密钥……在平台维护里核对公钥指纹」，把运维推向恰好那两个毁灭性动作——接受待确认公钥，或者重新生成租户签名密钥。

**「热更新不碰签名密钥所以信任等级更低」是假等价。** 热更新实例的产物是 JS bundle，服务端在下发那一刻用租户 OTA 私钥签名并推给每台设备；`applyStrategy: immediate` 的语义是两分钟内全量设备强制重启进新包（`build_ota_jobs.go:27-28`）。对一个钱包 App，这是**对全部用户设备的静默 RCE，不需要用户做任何动作**——就即时爆炸半径而言，不比偷到 keystore 小。`nativeFingerprint` 那道闸挡不住恶意代理：它比的是代理自己写进 manifest 的那个字符串（`internal/api/ota_fingerprint.go:49-62`），bundle 和指纹都由代理产出，它只挡失误。唯一真实的控制是「修订落成 `verified`，发布是管理端另一次带 reason 的动作」（`build_ota_jobs.go:231-234`）——那是真控制，但它防不住「攻击者植入 payload 后等运维点发布」，因为运维点的正是他自己发起的那次构建。

**新增的配错态。** `kinds` 若按 `platforms` 的规则处理（非法值丢弃、全空默认全部）就是 fail-open：`BUILD_AGENT_KINDS=OTA`（大写）或拼错 → 全被丢弃 → 默认全部 → 那个故意读不到 agent 私钥的实例开始领安装包任务。另有一个 TOFU 竞态：如果热更新实例先于安装包实例启动、而服务端还没有公钥记录，`registerBuildAgentKey` 对第一个登记者**零确认直接固定**（`build_agent_key.go:97-107`），此后每一把密钥都封给低信任用户的公钥。

**如果将来真要重开这个方案**，最低条件是：每个实例独立的 pnpm store（不是共用）；服务端侧的能力切分（独立的 OTA 令牌，只能 claim `kind=ota`，**不能**触达 `/public-key` 和 `/keystore-checks`）；`kinds` 两侧都 fail-closed（给了值但全非法 → 启动失败 / 400，只有完全省略才等于全部）；`verifyPendingKeystores` 挂在「本实例构建 apk」上；新 unit 的沙箱不能照抄（`ReadWritePaths` 要收窄，加 `InaccessiblePaths=/var/lib/rn-build-agent`、`ProtectProc=invisible`、`UMask=0077`）；以及显式配置 `BUILD_AGENT_STATE_DIR` 而不是让它从 workspace 推导。

## 8. 多台打包机需要什么（本次不做）

**加一台安装包打包机，等于不可逆地把 Android 签名密钥的明文接触面扩大一台。** 说不可逆是因为移除 ≠ 撤销：下线的那台机器曾经持有过明文，而真正撤销的唯一办法是换签名密钥，那会让已经发出去的 App 全部装不上升级包。所以台数应该按「愿意让几台机器永久地知道这把密钥」来定，不是按吞吐定。

**热更新打包机不受这条约束——但它也不是「随意横向扩」**（初稿这么写，已删除）。理由见 §7：它的产物是会被推到全部设备并立即执行的代码。它可以扩，但每一台的信任等级和安装包机同级，只是失效方式不同。

真要做，至少需要：

1. **封装改成多收件人**。现在是一对一：`SealTo(bundle, agentKey.Current)`（`internal/buildkeystore/recipient.go:96-145`），服务端只记一把当前公钥。改法是存一个 `Sealed` 列表、一个收件人一份；`Sealed` 本来就带 `RecipientKeyID`（`:136`），代理按自己的指纹挑。bundle 只有几 KB，不需要动任何密码学原语。
2. **存量密钥用人工重新上传原始 `.jks`**（同一个文件，签名身份不变）。
3. **代理身份可认证**——`claimed_by` 或收件人列表一旦开始影响明文流向，自报身份就必须先死。这是 1 和 2 的**前置条件**，不是后续优化。
4. 每代理在途上限 1 条。
5. **排队顺序的保护**。多机时同租户的 101 和 102 会并行，102 先入库之后 101 上传会吃 409 `RELEASE_VERSION_NOT_INCREASING`（`internal/api/simplified_releases.go:376-382`）——构建整个跑完了才失败。§3.5 的在途闸恰好堵住这条，届时它从公平性措施升级成正确性措施。

### 已否决：由打包机「转封」存量密钥

初稿提议让当前那台机器接一个转封任务：它能打开盒子，本地重封给新的收件人集合，服务端全程见不到明文。**否决。**

谁能把一把公钥放进那个收件人集合，谁就拿到明文 keystore 封给自己的密文。而今天收件人的写入口之一是 `registerBuildAgentKey` 在无记录时用**代理令牌、零确认**直接固定（`build_agent_key.go:97-107`）。转封会把 build-service 那条承重论证从「服务端读不到签名密钥」变成「服务端读不到签名密钥，**除非**它往收件人列表里写一行，然后请那台读得到的机器把密钥交出来」。这正是「服务端不在打包机上执行命令」那条边界被换了个动词重新打开：它**就是**一条命令，只是叫转封。

人工重新上传严格更安全，用它。若将来非做转封不可，最低条件现在写死：目标集合里每一把公钥必须已由人工核对指纹接受过；转封任务携带完整目标指纹列表，代理拒绝任何没在已接受记录里见过的指纹；转封是独立的管理端动作、有自己的审计事件；且**不可能**用打包机令牌触发。

## 9. 待实测（不进本次范围）

**Gradle build cache**。每次构建都是全新 worktree + `expo prebuild --clean`（`android/` 是 gitignore 的，每次从零生成），增量编译完全失效，现在复用的只有依赖缓存（那 6.3 GB）。`org.gradle.caching=true` 能跨目录复用任务产物，租户差异都在输入里（tenant.json、图标、google-services.json、app.config），缓存键天然区分。

但它和依赖校验门禁（`gradle/verification-metadata.xml`）怎么互动没有验证过，缓存本身也会持续增长。**必须实测再决定，不要当成结论。**

**热更新构建的实际时长**。整个仓库里没有一个实测数。§3.4 的排队时长列上线后顺带就能看到。
