package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"strings"
	"testing"
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
	c, recorder := testContext(t, tenant, "PUT", "/v1/admin/build-icons", map[string]any{
		"icons": map[string]any{
			"icon":              pngOf(512, 512),
			"androidForeground": pngOf(512, 512),
			"androidMonochrome": pngOf(512, 512),
		},
		"reason": "上传启动图标", "confirm": true,
	})
	c.Set("actorId", "tester")
	s.updateBuildIcons(c)
	if recorder.Code != 200 {
		t.Fatalf("保存失败: %d %s", recorder.Code, recorder.Body.String())
	}

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
	save := func(value string) *server {
		c, recorder := testContext(t, tenant, "PUT", "/v1/admin/build-icons", map[string]any{
			"icons": map[string]any{"icon": value}, "reason": "改图标", "confirm": true,
		})
		c.Set("actorId", "tester")
		s.updateBuildIcons(c)
		if recorder.Code != 200 {
			t.Fatalf("保存失败: %d %s", recorder.Code, recorder.Body.String())
		}
		return s
	}
	save(pngOf(512, 512))
	icons, _ := s.buildIconsFor(context.Background(), tenant)
	if _, ok := icons["icon"]; !ok {
		t.Fatal("没存进去")
	}
	save("")
	icons, _ = s.buildIconsFor(context.Background(), tenant)
	if _, ok := icons["icon"]; ok {
		t.Fatal("空串应当把它删掉")
	}
}

func keysOf(m map[string]string) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}
