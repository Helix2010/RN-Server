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
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const brandingConfigKey = "branding"
const brandingMaxAssetBytes int64 = 5 * 1024 * 1024

var defaultBrandingConfig = map[string]any{
	"schemaVersion": 1,
	"version":       1,
	"enabled":       true,
	"launch": map[string]any{
		"enabled":         true,
		"minDisplayMs":    700,
		"maxDisplayMs":    1800,
		"messages":        map[string]any{"titleKey": "launch.title", "subtitleKey": "launch.subtitle"},
		"animation":       map[string]any{"type": "fade_scale", "durationMs": 360},
		"defaultVisual":   map[string]any{"light": map[string]any{"backgroundColor": "#F4F7FB"}, "dark": map[string]any{"backgroundColor": "#0B1220"}},
		"localeOverrides": map[string]any{},
	},
	"cachePolicy": map[string]any{"maxBytes": 20971520, "keepVersions": 2, "staleAfterSeconds": 604800},
}

func cloneMap(input map[string]any) map[string]any {
	raw, _ := json.Marshal(input)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

func mergeBranding(global, tenant map[string]any) map[string]any {
	out := cloneMap(global)
	var merge func(map[string]any, map[string]any)
	merge = func(dst, src map[string]any) {
		for key, value := range src {
			if child, ok := value.(map[string]any); ok {
				if existing, ok := dst[key].(map[string]any); ok {
					merge(existing, child)
				} else {
					dst[key] = cloneMap(child)
				}
				continue
			}
			dst[key] = value
		}
	}
	merge(out, tenant)
	return out
}

func brandingDiff(base, value map[string]any) map[string]any {
	result := map[string]any{}
	for key, candidate := range value {
		baseline, exists := base[key]
		candidateMap, candidateIsMap := candidate.(map[string]any)
		baselineMap, baselineIsMap := baseline.(map[string]any)
		if candidateIsMap && baselineIsMap {
			if child := brandingDiff(baselineMap, candidateMap); len(child) > 0 {
				result[key] = child
			}
			continue
		}
		candidateRaw, _ := json.Marshal(candidate)
		baselineRaw, _ := json.Marshal(baseline)
		if !exists || !bytes.Equal(candidateRaw, baselineRaw) {
			result[key] = candidate
		}
	}
	return result
}

func (s *server) globalBranding(ctx context.Context) (map[string]any, error) {
	config := cloneMap(defaultBrandingConfig)
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT config_value FROM app_configs WHERE config_key=? AND tenant_id=0 LIMIT 1`, brandingConfigKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return config, nil
	}
	if err != nil {
		return nil, err
	}
	var stored map[string]any
	if json.Unmarshal(raw, &stored) != nil {
		return nil, errors.New("invalid global branding configuration")
	}
	return mergeBranding(config, stored), nil
}

func (s *server) brandingRecord(ctx context.Context, tenant string) (map[string]any, string, int, string, time.Time, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT CAST(tenant_id AS CHAR),config_value,version,updated_by,updated_at FROM app_configs WHERE config_key=? AND tenant_id IN (?,0) ORDER BY tenant_id ASC`, brandingConfigKey, tenant)
	if err != nil {
		return nil, "", 0, "", time.Time{}, err
	}
	defer rows.Close()
	global := cloneMap(defaultBrandingConfig)
	current := map[string]any{}
	var source, updatedBy string
	var version int
	var updated time.Time
	for rows.Next() {
		var tenantID string
		var raw []byte
		var itemVersion int
		var itemBy string
		var itemUpdated time.Time
		if err := rows.Scan(&tenantID, &raw, &itemVersion, &itemBy, &itemUpdated); err != nil {
			return nil, "", 0, "", time.Time{}, err
		}
		var item map[string]any
		if json.Unmarshal(raw, &item) != nil {
			return nil, "", 0, "", time.Time{}, errors.New("invalid branding configuration")
		}
		if tenantID == "0" {
			global = mergeBranding(global, item)
		} else {
			current = item
			source, version, updatedBy, updated = tenantID, itemVersion, itemBy, itemUpdated
		}
	}
	if err := rows.Err(); err != nil {
		return nil, "", 0, "", time.Time{}, err
	}
	if source == "" {
		source, version, updatedBy, updated = "0", 1, "system-branding", time.Now().UTC()
	}
	return mergeBranding(global, current), source, version, updatedBy, updated, nil
}

func (s *server) getBranding(c *gin.Context) {
	config, source, version, updatedBy, updated, err := s.brandingRecord(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, 500, "BRANDING_QUERY_FAILED", "Unable to load branding configuration")
		return
	}
	c.JSON(http.StatusOK, gin.H{"config": config, "metadata": gin.H{"sourceTenant": source, "version": version, "updatedBy": updatedBy, "updatedAt": iso(updated)}})
}

func (s *server) updateBranding(c *gin.Context) {
	var body struct {
		Config          map[string]any `json:"config"`
		ExpectedVersion int            `json:"expectedVersion"`
		Reason          string         `json:"reason"`
		Confirm         bool           `json:"confirm"`
	}
	if decode(c, &body) != nil || body.Config == nil || body.ExpectedVersion < 0 || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 {
		problem(c, 400, "INVALID_BRANDING_CONFIG", "config, expectedVersion, reason and confirm=true are required")
		return
	}
	if err := validateBrandingConfig(body.Config); err != nil {
		problem(c, 422, "INVALID_BRANDING_CONFIG", err.Error())
		return
	}
	if err := s.validateBrandingLanguages(c.Request.Context(), tenantID(c), body.Config); err != nil {
		problem(c, 422, "INVALID_BRANDING_LANGUAGE", err.Error())
		return
	}
	if err := s.prepareBrandingAssets(c.Request.Context(), tenantID(c), body.Config); err != nil {
		problem(c, 422, "INVALID_BRANDING_ASSET", err.Error())
		return
	}
	_, source, currentVersion, _, _, err := s.brandingRecord(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, 500, "BRANDING_QUERY_FAILED", "Unable to load branding configuration")
		return
	}
	if source != tenantID(c) {
		currentVersion = 0
	}
	if body.ExpectedVersion != currentVersion {
		problem(c, 409, "STALE_BRANDING_CONFIG", "Branding configuration changed; refresh and retry")
		return
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, 500, "BRANDING_SAVE_FAILED", "Unable to save branding configuration")
		return
	}
	defer tx.Rollback()
	var result sql.Result
	newVersion := 1
	if source == tenantID(c) {
		newVersion = currentVersion + 1
	}
	body.Config["version"] = newVersion
	globalConfig, err := s.globalBranding(c.Request.Context())
	if err != nil {
		problem(c, 500, "BRANDING_QUERY_FAILED", "Unable to load global branding configuration")
		return
	}
	storedConfig := brandingDiff(globalConfig, body.Config)
	storedConfig["version"] = newVersion
	raw, _ := json.Marshal(storedConfig)
	if source == tenantID(c) {
		result, err = tx.ExecContext(c.Request.Context(), `UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`, raw, actor(c), now, tenantID(c), brandingConfigKey, currentVersion)
	} else {
		result, err = tx.ExecContext(c.Request.Context(), `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,?,?,?)`, tenantID(c), brandingConfigKey, raw, 1, actor(c), now)
	}
	if err != nil {
		problem(c, 500, "BRANDING_SAVE_FAILED", "Unable to save branding configuration")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, 409, "STALE_BRANDING_CONFIG", "Branding configuration changed; refresh and retry")
		return
	}
	event := newAudit(tenantID(c), actor(c), "branding_update", "app-config", brandingConfigKey, strings.TrimSpace(body.Reason), requestID(c), map[string]any{"version": newVersion})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, 500, "BRANDING_SAVE_FAILED", "Unable to save branding audit")
		return
	}
	config, source, version, updatedBy, updated, _ := s.brandingRecord(c.Request.Context(), tenantID(c))
	c.JSON(http.StatusOK, gin.H{"config": config, "metadata": gin.H{"sourceTenant": source, "version": version, "updatedBy": updatedBy, "updatedAt": iso(updated)}, "savedAt": iso(now)})
}

func (s *server) validateBrandingLanguages(ctx context.Context, tenant string, config map[string]any) error {
	settings, _, _, err := s.effectiveLanguageSettings(ctx, tenant)
	if err != nil {
		return errors.New("language settings are unavailable")
	}
	launch := object(config["launch"])
	for code := range object(launch["localeOverrides"]) {
		language, exists := settings.Languages[code]
		if !exists || !language.Enabled || !validLanguageCode(code) {
			return fmt.Errorf("branding locale %s is not configured and enabled", code)
		}
	}
	return nil
}

func validateBrandingConfig(config map[string]any) error {
	schema, ok := config["schemaVersion"].(float64)
	if !ok {
		if integer, integerOK := config["schemaVersion"].(int); integerOK {
			schema, ok = float64(integer), true
		}
	}
	if !ok || schema != 1 {
		return errors.New("schemaVersion must be 1")
	}
	if launch, ok := config["launch"].(map[string]any); ok {
		if messages, ok := launch["messages"].(map[string]any); ok {
			for _, key := range []string{"titleKey", "subtitleKey"} {
				if value, ok := messages[key].(string); !ok || strings.TrimSpace(value) == "" {
					return fmt.Errorf("launch.messages.%s is required", key)
				}
			}
		}
	}
	return nil
}

func (s *server) prepareBrandingAssets(ctx context.Context, tenant string, value any) error {
	item, ok := value.(map[string]any)
	if !ok {
		if list, ok := value.([]any); ok {
			for _, child := range list {
				if err := s.prepareBrandingAssets(ctx, tenant, child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if encoded, ok := item["uploadToken"].(string); ok && strings.TrimSpace(encoded) != "" {
		token, err := s.decodeBrandingAssetToken(tenant, encoded)
		if err != nil {
			return errors.New("branding upload token is invalid or expired")
		}
		if !oneOf(token.ContentType, "image/png", "image/jpeg") {
			return errors.New("branding asset must be PNG or JPEG")
		}
		client, _, err := s.storageClientForTenant(ctx, tenant)
		if err != nil {
			return errors.New("branding storage is unavailable")
		}
		size, contentType, err := client.Head(ctx, token.ObjectKey)
		if err != nil || size != token.Size {
			return errors.New("uploaded branding asset is missing or has an unexpected size")
		}
		body, err := client.Get(ctx, token.ObjectKey)
		if err != nil {
			return errors.New("unable to read uploaded branding asset")
		}
		raw, readErr := io.ReadAll(io.LimitReader(body, token.Size+1))
		_ = body.Close()
		if readErr != nil || int64(len(raw)) != token.Size {
			return errors.New("unable to read complete branding asset")
		}
		hash := sha256.Sum256(raw)
		decoded, _, decodeErr := image.Decode(bytes.NewReader(raw))
		if decodeErr != nil {
			return errors.New("uploaded branding asset is not a valid image")
		}
		bounds := decoded.Bounds()
		width, height := bounds.Dx(), bounds.Dy()
		if width < 64 || height < 64 || width > 4096 || height > 4096 {
			return errors.New("branding image dimensions must be between 64 and 4096 pixels")
		}
		for key := range item {
			delete(item, key)
		}
		item["assetId"], item["objectKey"], item["fileUrl"] = token.ID, token.ObjectKey, "/v1/mobile/branding/assets/"+token.ID
		item["fileName"], item["mimeType"], item["size"] = token.FileName, text(contentType, token.ContentType), token.Size
		item["sha256"], item["width"], item["height"] = hex.EncodeToString(hash[:]), width, height
		return nil
	}
	for _, child := range item {
		if err := s.prepareBrandingAssets(ctx, tenant, child); err != nil {
			return err
		}
	}
	return nil
}

func resolveBranding(config map[string]any, locale, fallback string, messages map[string]string) map[string]any {
	launch := object(config["launch"])
	defaultVisual := object(launch["defaultVisual"])
	localeOverrides := object(launch["localeOverrides"])
	selectedOverride := object(localeOverrides[locale])
	if len(selectedOverride) == 0 && fallback != locale {
		selectedOverride = object(localeOverrides[fallback])
	}
	visuals := mergeBranding(defaultVisual, selectedOverride)
	messageConfig := object(launch["messages"])
	titleKey, subtitleKey := text(messageConfig["titleKey"], "launch.title"), text(messageConfig["subtitleKey"], "launch.subtitle")
	return map[string]any{
		"schemaVersion": config["schemaVersion"], "version": config["version"], "enabled": config["enabled"],
		"selectedLocale": locale, "fallbackLocale": fallback,
		"launch":      map[string]any{"enabled": launch["enabled"], "minDisplayMs": launch["minDisplayMs"], "maxDisplayMs": launch["maxDisplayMs"], "animation": launch["animation"], "title": messages[titleKey], "subtitle": messages[subtitleKey], "visuals": visuals},
		"cachePolicy": config["cachePolicy"],
	}
}

type brandingAssetToken struct {
	ID, TenantID, ObjectKey, FileName, ContentType string
	Size, ExpiresAt                                int64
}

func (s *server) encodeBrandingAssetToken(v brandingAssetToken) (string, error) {
	if s.secrets == nil {
		return "", errors.New("storage master key unavailable")
	}
	raw, _ := json.Marshal(v)
	enc, err := s.secrets.Encrypt(string(raw), "branding-asset:"+v.TenantID)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(enc), nil
}

func (s *server) decodeBrandingAssetToken(tenant, encoded string) (brandingAssetToken, error) {
	var v brandingAssetToken
	if s.secrets == nil || strings.TrimSpace(encoded) == "" {
		return v, errors.New("branding asset token unavailable")
	}
	enc, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return v, errors.New("invalid branding asset token")
	}
	plain, err := s.secrets.Decrypt(enc, "branding-asset:"+tenant)
	if err != nil || json.Unmarshal([]byte(plain), &v) != nil || v.TenantID != tenant || time.Now().UTC().Unix() > v.ExpiresAt {
		return v, errors.New("invalid or expired branding asset token")
	}
	return v, nil
}

func brandingTokenFromRequest(c *gin.Context) string {
	if v := strings.TrimSpace(c.GetHeader("x-branding-asset-token")); v != "" {
		return v
	}
	return strings.TrimSpace(c.Query("token"))
}

func (s *server) createBrandingAssetUpload(c *gin.Context) {
	var body struct {
		FileName, ContentType, AssetType, Locale, Theme string
		Size                                            int64
	}
	if decode(c, &body) != nil {
		problem(c, 400, "INVALID_BRANDING_UPLOAD", "Invalid branding upload payload")
		return
	}
	body.FileName = path.Base(strings.TrimSpace(body.FileName))
	body.ContentType = strings.ToLower(strings.TrimSpace(body.ContentType))
	body.AssetType = strings.ToLower(strings.TrimSpace(body.AssetType))
	body.Locale = strings.TrimSpace(body.Locale)
	body.Theme = strings.ToLower(strings.TrimSpace(body.Theme))
	if body.FileName == "" || body.FileName == "." || body.Size < 1 || body.Size > brandingMaxAssetBytes || !oneOf(body.AssetType, "launch_logo", "launch_background") || !oneOf(body.Theme, "", "light", "dark") || (body.Locale != "" && !validLanguageCode(body.Locale)) {
		problem(c, 422, "INVALID_BRANDING_UPLOAD", "fileName, size, assetType or theme is invalid")
		return
	}
	client, prefix, err := s.storageClientForTenant(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, 503, "STORAGE_UNAVAILABLE", "Release storage is not configured")
		return
	}
	locale := strings.TrimSpace(body.Locale)
	if locale == "" {
		locale = "default"
	}
	theme := strings.TrimSpace(body.Theme)
	if theme == "" {
		theme = "shared"
	}
	now := time.Now().UTC()
	id := "brand_" + randomID(16)
	key := strings.TrimLeft(path.Join(prefix, "tenants", tenantID(c), "branding", body.AssetType, locale, theme, id+path.Ext(body.FileName)), "/")
	value := brandingAssetToken{ID: id, TenantID: tenantID(c), ObjectKey: key, FileName: body.FileName, ContentType: body.ContentType, Size: body.Size, ExpiresAt: now.Add(time.Duration(s.cfg.ArtifactUploadTTL) * time.Second).Unix()}
	token, err := s.encodeBrandingAssetToken(value)
	if err != nil {
		problem(c, 503, "BRANDING_TOKEN_UNAVAILABLE", "Branding upload signing is not configured")
		return
	}
	uploadURL := absoluteURL(c, "/v1/admin/branding/assets/upload")
	headers := map[string]string{"content-type": body.ContentType, "x-branding-asset-token": token}
	requiresCredentials := true
	if s.cfg.ArtifactUploadMode == "direct" {
		uploadURL, headers, err = client.PresignPut(c.Request.Context(), key, body.ContentType, body.Size, time.Duration(s.cfg.ArtifactUploadTTL)*time.Second)
		if err != nil {
			problem(c, 502, "BRANDING_UPLOAD_CREATE_FAILED", "Unable to create storage upload URL")
			return
		}
		requiresCredentials = false
	}
	c.JSON(http.StatusCreated, gin.H{"asset": gin.H{"id": id, "token": token, "objectKey": key, "fileName": body.FileName, "contentType": body.ContentType, "size": body.Size, "expiresAt": iso(time.Unix(value.ExpiresAt, 0).UTC())}, "upload": gin.H{"method": "PUT", "url": uploadURL, "headers": headers, "expiresAt": iso(time.Unix(value.ExpiresAt, 0).UTC()), "requiresCredentials": requiresCredentials}})
}

func (s *server) uploadBrandingAsset(c *gin.Context) {
	if s.cfg.ArtifactUploadMode != "proxy" {
		problem(c, 404, "BRANDING_UPLOAD_PROXY_DISABLED", "Server-side branding upload is disabled")
		return
	}
	v, err := s.decodeBrandingAssetToken(tenantID(c), brandingTokenFromRequest(c))
	if err != nil {
		problem(c, 401, "INVALID_BRANDING_TOKEN", "Invalid branding asset token")
		return
	}
	if c.Request.ContentLength != v.Size {
		problem(c, 411, "BRANDING_UPLOAD_SIZE_MISMATCH", "Uploaded file size does not match declaration")
		return
	}
	size, err := s.receiveAndStoreArtifact(c, v.ObjectKey, v.ContentType, v.Size)
	if err != nil {
		problem(c, 502, "BRANDING_UPLOAD_FAILED", "Unable to store branding asset")
		return
	}
	c.JSON(200, gin.H{"asset": gin.H{"id": v.ID, "token": brandingTokenFromRequest(c), "objectKey": v.ObjectKey, "fileName": v.FileName, "contentType": v.ContentType, "size": size}})
}

func (s *server) deleteBrandingAsset(c *gin.Context) {
	v, err := s.decodeBrandingAssetToken(tenantID(c), brandingTokenFromRequest(c))
	if err != nil {
		problem(c, 401, "INVALID_BRANDING_TOKEN", "Invalid branding asset token")
		return
	}
	if client, _, e := s.storageClientForTenant(c.Request.Context(), tenantID(c)); e == nil {
		_ = client.Delete(c.Request.Context(), v.ObjectKey)
	}
	c.JSON(200, gin.H{"deleted": true})
}

func (s *server) brandingAsset(c *gin.Context) {
	config, _, _, _, _, err := s.brandingRecord(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, 503, "BRANDING_UNAVAILABLE", "Branding configuration is unavailable")
		return
	}
	asset, ok := findBrandingAsset(config, c.Param("id"))
	if !ok {
		problem(c, 404, "BRANDING_ASSET_NOT_FOUND", "Branding asset not found")
		return
	}
	key, _ := asset["objectKey"].(string)
	if key == "" {
		problem(c, 404, "BRANDING_ASSET_NOT_FOUND", "Branding asset not found")
		return
	}
	resourceTenant := tenantID(c)
	if strings.Contains(key, "/tenants/0/") {
		resourceTenant = "0"
	} else if !strings.Contains(key, "/tenants/"+tenantID(c)+"/") {
		problem(c, 404, "BRANDING_ASSET_NOT_FOUND", "Branding asset not found")
		return
	}
	client, _, err := s.storageClientForTenant(c.Request.Context(), resourceTenant)
	if err != nil {
		problem(c, 503, "STORAGE_UNAVAILABLE", "Release storage is unavailable")
		return
	}
	body, err := client.Get(c.Request.Context(), key)
	if err != nil {
		problem(c, 404, "BRANDING_ASSET_NOT_FOUND", "Branding asset not found")
		return
	}
	defer body.Close()
	if mime, ok := asset["mimeType"].(string); ok && mime != "" {
		c.Header("Content-Type", mime)
	} else {
		c.Header("Content-Type", "application/octet-stream")
	}
	if size, ok := asset["size"].(float64); ok {
		c.Header("Content-Length", fmt.Sprint(int64(size)))
	}
	c.Header("Cache-Control", "public, max-age=31536000, immutable")
	_, _ = io.Copy(c.Writer, body)
}

func findBrandingAsset(value any, id string) (map[string]any, bool) {
	if item, ok := value.(map[string]any); ok {
		if candidate, ok := item["assetId"].(string); ok && candidate == id {
			return item, true
		}
		for _, child := range item {
			if found, ok := findBrandingAsset(child, id); ok {
				return found, true
			}
		}
	} else if list, ok := value.([]any); ok {
		for _, child := range list {
			if found, ok := findBrandingAsset(child, id); ok {
				return found, true
			}
		}
	}
	return nil, false
}
