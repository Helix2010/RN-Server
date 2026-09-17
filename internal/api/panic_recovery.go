package api

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strings"

	"github.com/gin-gonic/gin"
)

// recoverPanics 取代 gin.Recovery()：gin 自带的那个在 debug 模式下把整份请求（请求行与全部请求头）原样打进
// 日志，只遮 Authorization——x-enrollment-code、x-machine-token、x-admin-key、Cookie 都会进日志（AGENTS.md
// 「禁止记录密码、token……」）。这里只记能定位问题又不含请求内容的东西：panic 值、方法、路由模板（不是原始路径，
// 路径参数与查询串可能带着标识）、request id、堆栈。响应是统一的 500 problem，不含 panic 值。
//
// 挂在 requestContext 之前（最外层），所以 panic 发生时 request id 通常已经设好；没设好（panic 出在
// requestContext 之前）就记空。
func recoverPanics() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			recovered := recover()
			if recovered == nil {
				return
			}
			if err, ok := recovered.(error); ok && errors.Is(err, http.ErrAbortHandler) {
				// net/http 的约定：静默中止这次响应并关掉连接。交还给它处理
				panic(recovered)
			}
			requestID, _ := c.Get("requestId")
			id, _ := requestID.(string)
			attributes := []any{"method", c.Request.Method, "route", c.FullPath(), "requestId", id}
			if connectionGone(recovered) {
				// 对端已经断开：写不出响应，也不值得一份堆栈
				slog.Warn("client connection closed while writing the response", append(attributes, "error", fmt.Sprint(recovered))...)
				c.Abort()
				return
			}
			slog.Error("recovered from a panic in a request handler", append(attributes, "panic", fmt.Sprint(recovered), "stack", string(debug.Stack()))...)
			if c.Writer.Written() {
				// 响应头已经发出去了，只能中止
				c.Abort()
				return
			}
			c.Abort()
			problem(c, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR", "The server hit an unexpected error; quote the requestId when reporting it")
		}()
		c.Next()
	}
}

// connectionGone 与 gin.Recovery 的判断一致：写响应时对端断开（broken pipe、connection reset）。
func connectionGone(recovered any) bool {
	err, ok := recovered.(error)
	if !ok {
		return false
	}
	var opErr *net.OpError
	var syscallErr *os.SyscallError
	if errors.As(err, &opErr) && errors.As(opErr, &syscallErr) {
		message := strings.ToLower(syscallErr.Error())
		return strings.Contains(message, "broken pipe") || strings.Contains(message, "connection reset by peer")
	}
	return false
}
