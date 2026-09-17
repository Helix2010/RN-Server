package api

import "strings"

// 打包任务的状态机（设计 android-signing-gate-2026-09-16「构建任务的状态与字段」、ADR 0019）。
//
// 安装包任务（Android）：queued → claimed → running → built（待签名）→ signing（签名中）→ succeeded。
// 安装包任务（iOS）：queued → claimed → running → succeeded——签名在 Mac 上的
// xcodebuild 里就发生了，没有未签名产物可以交给签名闸（见 ios_build_release.go）。
// 热更新任务不经过签名闸：queued → claimed → running → succeeded。
//
// **所有按状态判断的 SQL 都从这张表取状态集合**，不在各处手写字面量。签名闸上线之前
// 这些集合散在十来个地方，加两个状态时漏改任何一处，表现都很隐蔽：漏了生成列，签名
// 期间同一个 build 号能再排一条；漏了回收，签名闸挂了任务永远停在 signing；漏了列表
// 筛选白名单，控制台按状态筛选直接 422。
const (
	jobQueued    = "queued"
	jobClaimed   = "claimed"
	jobRunning   = "running"
	jobBuilt     = "built"
	jobSigning   = "signing"
	jobSucceeded = "succeeded"
	jobFailed    = "failed"
	jobCanceled  = "canceled"
)

const (
	jobKindAPK = "apk"
	jobKindOTA = "ota"
)

// buildJobStatuses 是 build_jobs.status 的全部取值，顺序即流转顺序。
var buildJobStatuses = []string{jobQueued, jobClaimed, jobRunning, jobBuilt, jobSigning, jobSucceeded, jobFailed, jobCanceled}

// 状态机里的事件。名字只在这个文件和测试里用，不进库、不进接口。
const (
	eventBuilderClaim     = "builder.claim"
	eventBuilderHeartbeat = "builder.heartbeat"
	eventBuilderFail      = "builder.fail"
	eventBuilderBuilt     = "builder.built"
	eventBuilderComplete  = "builder.complete"
	// iOS 安装包：Mac 上 xcodebuild 导出的那一刻签名就已经发生，没有未签名产物可以
	// 交给签名闸，所以它一步到 succeeded，不经过 built / signing（signer.go 的认领
	// 本来就带 platform='android'）。事件按 kind 归到 apk 下，平台条件在处理函数里
	eventBuilderIOSRelease = "builder.ios-release"
	eventDispatchFail      = "server.dispatch-fail"
	eventReapBuild         = "reaper.build-timeout"
	eventAdminCancel       = "admin.cancel"
	eventAdminForceFail    = "admin.force-fail"
	eventSignerClaim       = "signer.claim"
	eventSignerHeartbeat   = "signer.heartbeat"
	eventSignerRelease     = "signer.release"
	eventSignerViolation   = "signer.reject-violation"
	eventSignerTransient   = "signer.reject-transient"
	eventSignerComplete    = "signer.complete"
	eventReapSign          = "reaper.sign-timeout"
	eventSignOvertaken     = "server.sign-overtaken"
	eventSignerUpload      = "signer.upload"
	eventSignerDownload    = "signer.download"
	eventBuilderUpload     = "builder.upload"
	eventBuilderOTAPayload = "builder.ota-payload"
)

// buildJobTransition 是状态机的一条边。To 有两个值的事件按条件分叉（例如回收：
// 重排次数没到上限退回排队，到了判失败）；To 等于 From 的是不改状态、只要求状态的
// 上报（心跳、上传、下载）。
type buildJobTransition struct {
	Event string
	Kinds []string
	From  []string
	To    []string
}

var buildJobTransitions = []buildJobTransition{
	{eventBuilderClaim, []string{jobKindAPK, jobKindOTA}, []string{jobQueued}, []string{jobClaimed}},
	{eventBuilderHeartbeat, []string{jobKindAPK, jobKindOTA}, []string{jobClaimed, jobRunning}, []string{jobRunning}},
	{eventBuilderUpload, []string{jobKindAPK}, []string{jobClaimed, jobRunning}, []string{jobClaimed, jobRunning}},
	{eventBuilderOTAPayload, []string{jobKindOTA}, []string{jobClaimed, jobRunning}, []string{jobClaimed, jobRunning}},
	{eventBuilderFail, []string{jobKindAPK, jobKindOTA}, []string{jobClaimed, jobRunning}, []string{jobFailed}},
	{eventBuilderBuilt, []string{jobKindAPK}, []string{jobClaimed, jobRunning}, []string{jobBuilt}},
	{eventBuilderComplete, []string{jobKindOTA}, []string{jobClaimed, jobRunning}, []string{jobSucceeded}},
	{eventBuilderIOSRelease, []string{jobKindAPK}, []string{jobClaimed, jobRunning}, []string{jobSucceeded}},
	// 认领那一刻就发现缺配置（租户被删、身份不全、基线失效）：当场判失败放出队列
	{eventDispatchFail, []string{jobKindAPK, jobKindOTA}, []string{jobClaimed}, []string{jobFailed}},
	{eventReapBuild, []string{jobKindAPK}, []string{jobClaimed, jobRunning}, []string{jobQueued, jobFailed}},
	{eventReapBuild, []string{jobKindOTA}, []string{jobClaimed, jobRunning}, []string{jobFailed}},
	// running 不能取消：取消停不下构建机上的进程，状态会骗人。built 可以：包还没签
	{eventAdminCancel, []string{jobKindAPK, jobKindOTA}, []string{jobQueued, jobClaimed}, []string{jobCanceled}},
	{eventAdminCancel, []string{jobKindAPK}, []string{jobBuilt}, []string{jobCanceled}},
	// signing 不能取消（签名闸可能正在签），只能带原因强制判失败；签名闸之后的迟到上报按编号拒绝
	{eventAdminForceFail, []string{jobKindAPK}, []string{jobSigning}, []string{jobFailed}},
	{eventSignerClaim, []string{jobKindAPK}, []string{jobBuilt}, []string{jobSigning}},
	{eventSignerHeartbeat, []string{jobKindAPK}, []string{jobSigning}, []string{jobSigning}},
	{eventSignerUpload, []string{jobKindAPK}, []string{jobSigning}, []string{jobSigning}},
	{eventSignerDownload, []string{jobKindAPK}, []string{jobSigning}, []string{jobSigning}},
	{eventSignerRelease, []string{jobKindAPK}, []string{jobSigning}, []string{jobBuilt}},
	{eventSignerViolation, []string{jobKindAPK}, []string{jobSigning}, []string{jobFailed}},
	{eventSignerTransient, []string{jobKindAPK}, []string{jobSigning}, []string{jobBuilt, jobFailed}},
	{eventSignerComplete, []string{jobKindAPK}, []string{jobSigning}, []string{jobSucceeded}},
	{eventReapSign, []string{jobKindAPK}, []string{jobSigning}, []string{jobBuilt, jobFailed}},
	// 构建期间该平台已经有了不低于它的发布（手工上传）：签出来也落不了库，派活前当场判失败
	{eventSignOvertaken, []string{jobKindAPK}, []string{jobBuilt}, []string{jobFailed}},
}

// buildJobEventFrom 返回某个事件在某种任务上允许的起始状态；kind 为空时取所有类型的并集。
func buildJobEventFrom(event, kind string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, t := range buildJobTransitions {
		if t.Event != event || (kind != "" && !containsString(t.Kinds, kind)) {
			continue
		}
		for _, from := range t.From {
			if !seen[from] {
				seen[from] = true
				out = append(out, from)
			}
		}
	}
	return orderedStatuses(out)
}

// buildJobTransitionAllowed 回答"这种任务在这个状态下能不能发生这个事件"。
func buildJobTransitionAllowed(event, kind, from string) bool {
	return containsString(buildJobEventFrom(event, kind), from)
}

// buildJobInFlightStatuses 是"还没有结论"的状态：占着 build 号，也挡着同租户后面的签名。
// 与迁移 54 的 live_build_number 表达式（去掉 succeeded）一致。
var buildJobInFlightStatuses = []string{jobQueued, jobClaimed, jobRunning, jobBuilt, jobSigning}

// buildJobTerminalStatuses 没有出边。
var buildJobTerminalStatuses = []string{jobSucceeded, jobFailed, jobCanceled}

// sqlStatusList 把状态集合写成 SQL 的 IN 列表。值全部来自上面的常量，不是用户输入。
func sqlStatusList(statuses []string) string {
	quoted := make([]string, 0, len(statuses))
	for _, status := range statuses {
		quoted = append(quoted, "'"+status+"'")
	}
	return strings.Join(quoted, ",")
}

// 各条 SQL 用到的状态集合，启动时算一次。
var (
	sqlBuilderActive   = sqlStatusList(buildJobEventFrom(eventBuilderHeartbeat, ""))
	sqlCancelableAPK   = sqlStatusList(buildJobEventFrom(eventAdminCancel, jobKindAPK))
	sqlCancelableOTA   = sqlStatusList(buildJobEventFrom(eventAdminCancel, jobKindOTA))
	sqlInFlight        = sqlStatusList(buildJobInFlightStatuses)
	sqlSignerActive    = sqlStatusList(buildJobEventFrom(eventSignerHeartbeat, jobKindAPK))
	sqlDispatchFailure = sqlStatusList(buildJobEventFrom(eventDispatchFail, ""))
)

func orderedStatuses(statuses []string) []string {
	out := make([]string, 0, len(statuses))
	for _, status := range buildJobStatuses {
		if containsString(statuses, status) {
			out = append(out, status)
		}
	}
	return out
}

func containsString(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}
