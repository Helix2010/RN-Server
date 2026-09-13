package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// 启动图标由租户在控制台维护，随任务下发，不再放在 App 仓库里。
//
// 这是最后一个还留在仓库里的按租户资源——tenant.json 和 google-services.json 都已经
// 搬到服务端了。留着它的代价是新租户建不了包：2026-09-13 predict-kim 第一次构建，
// 密钥、身份、google-services 全部正常，倒在
// `ENOENT: ./assets/tenants/predict-kim/icon.png` 上。而"加一个租户要往 App 仓库提交
// 四个 png"这件事，本身就把租户自助这条路堵死了。
//
// 图标不是机密（它原样编进每个 APK），所以和 google-services.json 一样按 base64 存在
// 配置里、随任务下发。单独一个 config key：图片是几百 KB，混进 build.android 会让
// 控制台每次打开打包配置都拖一坨二进制。
const buildIconsConfigKey = "build.icons"

// 四个名字是约定，和 app.config.ts 里 tenantAsset() 拼的路径一一对应
var buildIconNames = []string{"icon", "androidForeground", "androidBackground", "androidMonochrome"}

var buildIconFileNames = map[string]string{
	"icon":              "icon.png",
	"androidForeground": "android-icon-foreground.png",
	"androidBackground": "android-icon-background.png",
	"androidMonochrome": "android-icon-monochrome.png",
}

const (
	// 1024×1024 的 PNG 通常在 1MB 以内。留 2MB 的余量，再大基本是没压缩过的原图，
	// 而它要经过任务下发通道，一次构建拉四张
	buildIconMaxBytes = 2 << 20
	buildIconMinSide  = 256
	buildIconMaxSide  = 2048
)

type buildIcon struct {
	Data   string `json:"data"` // base64 的 PNG
	SHA256 string `json:"sha256"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
	Size   int    `json:"size"`
}

type buildIcons map[string]buildIcon

func (s *server) buildIconsFor(ctx context.Context, tenant string) (buildIcons, error) {
	var raw []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT config_value FROM app_configs WHERE tenant_id=? AND config_key=? LIMIT 1`,
		tenant, buildIconsConfigKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return buildIcons{}, nil
	}
	if err != nil {
		return nil, err
	}
	icons := buildIcons{}
	if err := json.Unmarshal(raw, &icons); err != nil {
		return buildIcons{}, nil
	}
	return icons, nil
}

// validateBuildIcon 挡住那些会在 prebuild 里才炸的图。
//
// prebuild 报的是一句 ENOENT 或者 sharp 的栈，看的人不知道是自己传错了东西。这里
// 报的是"这不是 PNG""不是正方形""边长 100 太小"。
func validateBuildIcon(encoded string) (buildIcon, error) {
	var icon buildIcon
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return icon, errors.New("图标不是合法的 base64")
	}
	if len(raw) == 0 {
		return icon, errors.New("图标是空的")
	}
	if len(raw) > buildIconMaxBytes {
		return icon, fmt.Errorf("图标 %d KB，超过 %d KB 上限——导出时压一下，它要随每次构建下发四张",
			len(raw)/1024, buildIconMaxBytes/1024)
	}
	config, format, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil || format != "png" {
		return icon, errors.New("图标必须是 PNG。JPEG 没有透明通道，自适应图标会露出白底")
	}
	if config.Width != config.Height {
		return icon, fmt.Errorf("图标必须是正方形，当前 %d×%d", config.Width, config.Height)
	}
	if config.Width < buildIconMinSide || config.Width > buildIconMaxSide {
		return icon, fmt.Errorf("图标边长要在 %d 到 %d 之间，当前 %d——小了在高密度屏上糊，大了白占体积",
			buildIconMinSide, buildIconMaxSide, config.Width)
	}
	sum := sha256.Sum256(raw)
	return buildIcon{
		Data:   base64.StdEncoding.EncodeToString(raw),
		SHA256: hex.EncodeToString(sum[:]),
		Width:  config.Width,
		Height: config.Height,
		Size:   len(raw),
	}, nil
}

// solidIcon 用一个纯色生成一张 PNG。
//
// 自适应图标的背景层多数情况下就是一块纯色，而那个颜色控制台上本来就有
// （appIdentity.iconBackgroundColor）。让人再导出一张 1024×1024 的纯色 png 传上来，
// 是拿一件机器能做的事去换一次人工。
func solidIcon(hexColor string) (buildIcon, error) {
	var icon buildIcon
	value := strings.TrimPrefix(strings.TrimSpace(hexColor), "#")
	if len(value) != 6 {
		return icon, errors.New("背景色必须是 #RRGGBB")
	}
	parsed, err := strconv.ParseUint(value, 16, 32)
	if err != nil {
		return icon, errors.New("背景色必须是 #RRGGBB")
	}
	const side = 512
	img := image.NewRGBA(image.Rect(0, 0, side, side))
	fill := color.RGBA{R: uint8(parsed >> 16), G: uint8(parsed >> 8 & 0xff), B: uint8(parsed & 0xff), A: 0xff}
	for y := 0; y < side; y++ {
		for x := 0; x < side; x++ {
			img.Set(x, y, fill)
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return icon, err
	}
	sum := sha256.Sum256(buf.Bytes())
	return buildIcon{
		Data:   base64.StdEncoding.EncodeToString(buf.Bytes()),
		SHA256: hex.EncodeToString(sum[:]),
		Width:  side, Height: side, Size: buf.Len(),
	}, nil
}

func (s *server) getBuildIcons(c *gin.Context) {
	icons, err := s.buildIconsFor(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_ICONS_INVALID", "Stored build.icons configuration is invalid")
		return
	}
	// 图片本身不回给列表：控制台要的是"传了没有、是什么尺寸"，预览走单独的取图接口
	view := gin.H{}
	for _, name := range buildIconNames {
		if icon, ok := icons[name]; ok {
			view[name] = gin.H{"configured": true, "sha256": icon.SHA256, "width": icon.Width, "height": icon.Height, "size": icon.Size}
		} else {
			view[name] = gin.H{"configured": false}
		}
	}
	c.JSON(http.StatusOK, gin.H{"icons": view, "required": buildIconNames, "maxBytes": buildIconMaxBytes})
}

// getBuildIcon 回一张图本身，给控制台做预览。
func (s *server) getBuildIcon(c *gin.Context) {
	icons, err := s.buildIconsFor(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_ICONS_INVALID", "Stored build.icons configuration is invalid")
		return
	}
	icon, ok := icons[c.Param("name")]
	if !ok {
		problem(c, http.StatusNotFound, "BUILD_ICON_NOT_FOUND", "This tenant has no such icon")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(icon.Data)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_ICONS_INVALID", "Stored icon is not decodable")
		return
	}
	c.Data(http.StatusOK, "image/png", raw)
}

func (s *server) updateBuildIcons(c *gin.Context) {
	var body struct {
		Icons   map[string]string `json:"icons"`
		Reason  string            `json:"reason"`
		Confirm bool              `json:"confirm"`
	}
	if decode(c, &body) != nil {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_ICONS", "Invalid build icons payload")
		return
	}
	if !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_ICONS", "reason and confirm=true are required")
		return
	}
	current, err := s.buildIconsFor(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_ICONS_INVALID", "Stored build.icons configuration is invalid")
		return
	}
	for name, encoded := range body.Icons {
		if _, known := buildIconFileNames[name]; !known {
			problem(c, http.StatusUnprocessableEntity, "INVALID_BUILD_ICONS",
				"unknown icon "+name+"; expected one of "+strings.Join(buildIconNames, ", "))
			return
		}
		// 空串是"删掉这一张"，让它回落到别的来源
		if strings.TrimSpace(encoded) == "" {
			delete(current, name)
			continue
		}
		icon, err := validateBuildIcon(encoded)
		if err != nil {
			problem(c, http.StatusUnprocessableEntity, "INVALID_BUILD_ICONS", name+"："+err.Error())
			return
		}
		current[name] = icon
	}
	value, err := json.Marshal(current)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_ICONS_SAVE_FAILED", "Unable to save the icons")
		return
	}
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(c.Request.Context(),
		`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,1,?,?)
		 ON DUPLICATE KEY UPDATE config_value=VALUES(config_value),version=app_configs.version+1,updated_by=VALUES(updated_by),updated_at=VALUES(updated_at)`,
		tenantID(c), buildIconsConfigKey, value, actor(c), now); err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_ICONS_SAVE_FAILED", "Unable to save the icons")
		return
	}
	// 审计记的是每一张的指纹：换图标等于换 App 在桌面上的样子，要能查是谁什么时候换的
	digests := map[string]any{}
	for name, icon := range current {
		digests[name] = icon.SHA256
	}
	s.auditNow(newAudit(tenantID(c), actor(c), "build_icons_update", "app-config", buildIconsConfigKey,
		strings.TrimSpace(body.Reason), requestID(c), digests))
	s.getBuildIcons(c)
}

// buildIconsForJob 组出随任务下发的那一份。
//
// 背景层没传就用 appIdentity 上那个颜色现生成一张——自适应图标的背景多数就是一块
// 纯色，而那个颜色控制台上本来就有。
func (s *server) buildIconsForJob(ctx context.Context, tenant string, identity appIdentity) (map[string]string, error) {
	icons, err := s.buildIconsFor(ctx, tenant)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for name, icon := range icons {
		out[buildIconFileNames[name]] = icon.Data
	}
	if _, ok := icons["androidBackground"]; !ok {
		if generated, err := solidIcon(identity.IconBackgroundColor); err == nil {
			out[buildIconFileNames["androidBackground"]] = generated.Data
		}
	}
	return out, nil
}
