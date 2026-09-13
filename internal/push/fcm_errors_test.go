package push

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// cannedFCM 把 FCM 的一次回应伪造出来。URL 是写死的 fcm.googleapis.com，所以换
// 的是 Transport 而不是地址。
type cannedFCM struct {
	status int
	body   string
}

func (c cannedFCM) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: c.status,
		Body:       io.NopCloser(strings.NewReader(c.body)),
		Header:     http.Header{},
	}, nil
}

func senderWith(status int, body string) *tenantSender {
	return &tenantSender{version: 1, projectID: "anyfun", client: &http.Client{Transport: cannedFCM{status, body}}}
}

// FCM 的失败分三类，处理方式完全不同。混在一起的代价很具体：
//
//   - SENDER_ID_MISMATCH 当成 token 失效 → 把一个好 token 永久作废，那台设备要等
//     下次注册才恢复，比"这条没发出去"坏得多。
//   - 凭据被吊销当成瞬时故障 → 五次重试、三十分钟退避，然后 last_error 是一句
//     "FCM status 403"，看的人从推送服务一路查到证书。
func TestFCMFailuresAreSortedIntoTheThreeKindsThatMatter(t *testing.T) {
	d := &Dispatcher{}
	data := map[string]string{"type": "test"}

	t.Run("token 失效：作废它", func(t *testing.T) {
		_, err := d.sendFCM(context.Background(), senderWith(404, `{"error":{"status":"NOT_FOUND"}}`), "tok", data, "t", "b", false)
		if _, ok := err.(invalidTokenError); !ok {
			t.Fatalf("404 应当判成 token 失效：%v", err)
		}
	})

	t.Run("项目不匹配：凭据错误，且绝不碰 token", func(t *testing.T) {
		body := `{"error":{"status":"INVALID_ARGUMENT","details":[{"errorCode":"SENDER_ID_MISMATCH"}]}}`
		_, err := d.sendFCM(context.Background(), senderWith(403, body), "tok", data, "t", "b", false)
		problem, ok := asCredentialError(err)
		if !ok || problem.code != "FCM_PROJECT_MISMATCH" {
			t.Fatalf("SENDER_ID_MISMATCH 应当判成凭据错误：%v", err)
		}
		// 这一条是本次改动的核心：token 是好的，错的是凭据
		if _, wrong := err.(invalidTokenError); wrong {
			t.Fatal("绝不能把 SENDER_ID_MISMATCH 当成 token 失效——那会让这台设备永久收不到推送")
		}
		if !strings.Contains(problem.detail, "anyfun") {
			t.Fatalf("报错要带上服务端用的是哪个项目：%q", problem.detail)
		}
	})

	t.Run("密钥被吊销：凭据错误", func(t *testing.T) {
		_, err := d.sendFCM(context.Background(), senderWith(401, `{"error":{"status":"UNAUTHENTICATED"}}`), "tok", data, "t", "b", false)
		problem, ok := asCredentialError(err)
		if !ok || problem.code != "FCM_CREDENTIAL_REJECTED" {
			t.Fatalf("401 应当判成凭据错误：%v", err)
		}
	})

	t.Run("其它失败仍然重试", func(t *testing.T) {
		_, err := d.sendFCM(context.Background(), senderWith(503, `{"error":{"status":"UNAVAILABLE"}}`), "tok", data, "t", "b", false)
		if _, ok := asCredentialError(err); ok {
			t.Fatalf("503 是瞬时故障，必须留给重试：%v", err)
		}
		if _, ok := err.(invalidTokenError); ok {
			t.Fatalf("503 不能作废 token：%v", err)
		}
	})

	t.Run("成功", func(t *testing.T) {
		id, err := d.sendFCM(context.Background(), senderWith(200, `{"name":"projects/anyfun/messages/1"}`), "tok", data, "t", "b", true)
		if err != nil || id != "projects/anyfun/messages/1" {
			t.Fatalf("正常发送：%q %v", id, err)
		}
	})
}

// 没配凭据不该变成"每个收件人一条错、全失败后再重试五次"。
func TestMissingCredentialsAreATerminalCredentialError(t *testing.T) {
	d := &Dispatcher{senders: map[string]*tenantSender{}}
	_, err := d.legacyEnvSender(context.Background())
	problem, ok := asCredentialError(err)
	if !ok || problem.code != "FCM_NOT_CONFIGURED" {
		t.Fatalf("没有任何凭据时应当是 FCM_NOT_CONFIGURED：%v", err)
	}
	if !strings.Contains(problem.detail, "平台默认") {
		t.Fatalf("报错要说清楚平台默认那一层也没有：%q", problem.detail)
	}
}
