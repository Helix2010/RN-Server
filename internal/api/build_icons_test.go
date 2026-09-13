package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func pngOf(width, height int) string {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	img.Set(0, 0, color.RGBA{A: 255})
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// 挡在这里的每一条，放过去都会变成 prebuild 里一句看不懂的错，而那要等两分钟
// 装完依赖才出现。
func TestValidateBuildIconRejectsWhatPrebuildWouldChokeOn(t *testing.T) {
	if _, err := validateBuildIcon(pngOf(1024, 1024)); err != nil {
		t.Fatalf("正常的 1024 见方 PNG 被拒了：%v", err)
	}

	for name, tc := range map[string]struct {
		input string
		want  string
	}{
		"不是 base64": {"这不是 base64", "base64"},
		"空的":        {"", "空"},
		"长方形":       {pngOf(1024, 512), "正方形"},
		"太小":        {pngOf(64, 64), "边长"},
		"太大":        {pngOf(4096, 4096), "边长"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := validateBuildIcon(tc.input)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("错误信息没点明原因：%v", err)
			}
		})
	}

	// 线上正在用的那两张是 2048×2048 / 2.6MB，不能被判成不合法
	if _, err := validateBuildIcon(pngOf(2048, 2048)); err != nil {
		t.Fatalf("2048 见方的图被拒了，而线上正在用这个尺寸：%v", err)
	}

	// JPEG 没有透明通道，自适应图标会露出白底——这类错在设备上才看得出来
	img := image.NewRGBA(image.Rect(0, 0, 1024, 1024))
	var buf bytes.Buffer
	_ = jpeg.Encode(&buf, img, nil)
	if _, err := validateBuildIcon(base64.StdEncoding.EncodeToString(buf.Bytes())); err == nil ||
		!strings.Contains(err.Error(), "PNG") {
		t.Fatalf("JPEG 应当被拒：%v", err)
	}
}

// 背景层多数就是一块纯色，而那个颜色控制台上本来就有。让人再导出一张纯色 png
// 上传，是拿一件机器能做的事去换一次人工。
func TestSolidIconIsGeneratedFromTheConfiguredColour(t *testing.T) {
	icon, err := solidIcon("#E9F0FF")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(icon.Data)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("生成的不是合法 PNG：%v", err)
	}
	r, g, b, a := decoded.At(10, 10).RGBA()
	if r>>8 != 0xE9 || g>>8 != 0xF0 || b>>8 != 0xFF || a>>8 != 0xFF {
		t.Fatalf("颜色不对：%d %d %d %d", r>>8, g>>8, b>>8, a>>8)
	}
	if decoded.Bounds().Dx() != decoded.Bounds().Dy() {
		t.Fatal("生成的不是正方形")
	}
	for _, bad := range []string{"", "红色", "#12345", "#GGGGGG"} {
		if _, err := solidIcon(bad); err == nil {
			t.Fatalf("%q 不该被接受", bad)
		}
	}
}

// 下发给打包机的是"文件名 → base64"，文件名必须和 app.config.ts 拼的路径对得上。
// 背景层没传时用配置里的颜色补一张，这样租户只需要传三张。
func TestDBBuildIconsForJobFillsInTheBackground(t *testing.T) {
	db := openTestDB(t)
	s := &server{db: db}
	tenant := testTenant(30)
	// 一张一个请求，连着发三张——这一条同时盯着"后一张不会把前一张覆盖掉"：
	// 四张存在同一个配置行里，读—改—写没锁住的话保存完只会剩最后一张
	for _, name := range []string{"icon", "androidForeground", "androidMonochrome"} {
		putBuildIcon(t, s, tenant, name, pngOf(512, 512), 200)
	}
	c, _ := testContext(t, tenant, "GET", "/v1/admin/build-icons", nil)

	out, err := s.buildIconsForJob(c.Request.Context(), tenant, appIdentity{IconBackgroundColor: "#112233"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"icon.png", "android-icon-foreground.png", "android-icon-monochrome.png", "android-icon-background.png"} {
		if out[want] == "" {
			t.Fatalf("下发里缺 %s：%v", want, keysOf(out))
		}
	}
	// 没传的那一张是现生成的纯色，颜色取自配置
	raw, _ := base64.StdEncoding.DecodeString(out["android-icon-background.png"])
	decoded, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	r, g, b, _ := decoded.At(5, 5).RGBA()
	if r>>8 != 0x11 || g>>8 != 0x22 || b>>8 != 0x33 {
		t.Fatalf("补的背景色不对：%d %d %d", r>>8, g>>8, b>>8)
	}
}

// 空串是"删掉这一张"，让它回落到仓库里那份——老租户的图标还在仓库里
func TestDBBuildIconsCanBeCleared(t *testing.T) {
	db := openTestDB(t)
	s := &server{db: db}
	tenant := testTenant(31)
	putBuildIcon(t, s, tenant, "icon", pngOf(512, 512), 200)
	icons, _ := s.buildIconsFor(context.Background(), tenant)
	if _, ok := icons["icon"]; !ok {
		t.Fatal("没存进去")
	}
	// 删一张走 DELETE，不再用"空串代表删除"——一张一个请求之后，空 body 和
	// "这一张没改"分不开
	c, recorder := testContext(t, tenant, "DELETE", "/v1/admin/build-icons/icon",
		map[string]any{"reason": "去掉这张", "confirm": true})
	c.Params = gin.Params{{Key: "name", Value: "icon"}}
	c.Set("actorId", "tester")
	s.deleteBuildIcon(c)
	if recorder.Code != 200 {
		t.Fatalf("删除失败: %d %s", recorder.Code, recorder.Body.String())
	}
	icons, _ = s.buildIconsFor(context.Background(), tenant)
	if _, ok := icons["icon"]; ok {
		t.Fatal("DELETE 之后它应当没了")
	}
}

func keysOf(m map[string]string) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}

// putBuildIcon 发一张图，断言状态码。
func putBuildIcon(t *testing.T, s *server, tenant, name, data string, want int) *httptest.ResponseRecorder {
	t.Helper()
	c, recorder := testContext(t, tenant, "PUT", "/v1/admin/build-icons/"+name,
		map[string]any{"data": data, "reason": "上传启动图标", "confirm": true})
	c.Params = gin.Params{{Key: "name", Value: name}}
	c.Set("actorId", "tester")
	s.updateBuildIcon(c)
	if recorder.Code != want {
		t.Fatalf("%s: 状态码 %d，期望 %d：%s", name, recorder.Code, want, recorder.Body.String())
	}
	return recorder
}

// 这一条盯的是 2026-09-13 那次故障：单张上限抬到了 6 MiB，而所有接口共用的 decode
// 还卡在 1 MiB，于是校验器接受的图永远送不进来——线上表现是三次 400，报错只说一句
// "payload 不合法"，看的人只会去换图片格式。
//
// 请求体上限现在由 buildIconMaxBytes 推出来，所以这里直接拿"一张接近单张上限的图"
// 去发：它必须能进来。
func TestDBBuildIconNearTheSizeLimitGetsThrough(t *testing.T) {
	db := openTestDB(t)
	s := &server{db: db}
	tenant := testTenant(32)

	// 噪声图：PNG 对纯色压得极狠，要逼近真实素材的体积只能给它压不动的内容
	big := noisyPNG(1400)
	raw, _ := base64.StdEncoding.DecodeString(big)
	if len(raw) < 1<<20 {
		t.Fatalf("这张测试图只有 %d 字节，压不到 1 MiB 以上就测不到那条旧上限", len(raw))
	}
	if len(raw) > buildIconMaxBytes {
		t.Fatalf("这张测试图 %d 字节，超过单张上限 %d，测的就不是同一件事了", len(raw), buildIconMaxBytes)
	}
	putBuildIcon(t, s, tenant, "icon", big, 200)

	icons, _ := s.buildIconsFor(context.Background(), tenant)
	if icons["icon"].Size != len(raw) {
		t.Fatalf("存进去的是 %d 字节，发上来的是 %d", icons["icon"].Size, len(raw))
	}
}

// 超过单张上限时要说"这张图太大"，而且是 413——回 400 加一句"payload 不合法"，
// 等于把唯一能自救的信息藏起来。
func TestDBBuildIconOverTheLimitSaysSo(t *testing.T) {
	db := openTestDB(t)
	s := &server{db: db}
	recorder := putBuildIcon(t, s, testTenant(33), "icon", noisyPNG(2048), http.StatusRequestEntityTooLarge)
	body := decodeBody(t, recorder)
	if body["code"] != "BUILD_ICON_TOO_LARGE" {
		t.Fatalf("code = %v", body["code"])
	}
	if detail, _ := body["detail"].(string); !strings.Contains(detail, "太大") {
		t.Fatalf("报错没说是大小的问题：%v", body["detail"])
	}
}

// noisyPNG 造一张压不动的 PNG，用来逼近体积上限。
func noisyPNG(side int) string {
	img := image.NewRGBA(image.Rect(0, 0, side, side))
	random := rand.New(rand.NewSource(1))
	for y := 0; y < side; y++ {
		for x := 0; x < side; x++ {
			img.Set(x, y, color.RGBA{uint8(random.Intn(256)), uint8(random.Intn(256)), uint8(random.Intn(256)), 255})
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}
