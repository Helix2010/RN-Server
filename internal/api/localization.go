package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
)

const (
	languagesConfigKey = "languages"
	appLanguageType    = 14
)

var languageCodePattern = regexp.MustCompile(`^[a-z]{2,3}(?:-[A-Z][a-z]{3})?(?:-(?:[A-Z]{2}|[0-9]{3}))?$`)
var messageKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)

type languageOverride struct {
	Label      *string `json:"label,omitempty"`
	NativeName *string `json:"nativeName,omitempty"`
	Enabled    *bool   `json:"enabled,omitempty"`
	Direction  *string `json:"direction,omitempty"`
	Sort       *int    `json:"sort,omitempty"`
}

type languageResource struct {
	Version     string `json:"version"`
	ObjectKey   string `json:"objectKey"`
	FileURL     string `json:"fileUrl"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	PublishedAt string `json:"publishedAt"`
}

type storedLanguagesConfig struct {
	SchemaVersion          int                         `json:"schemaVersion,omitempty"`
	FallbackLanguage       string                      `json:"fallbackLanguage,omitempty"`
	RefreshIntervalSeconds int                         `json:"refreshIntervalSeconds,omitempty"`
	Languages              map[string]languageOverride `json:"languages,omitempty"`
	Resources              map[string]languageResource `json:"resources,omitempty"`
	DirtyLanguages         map[string]bool             `json:"dirtyLanguages,omitempty"`
	FailedLanguages        map[string]string           `json:"failedLanguages,omitempty"`
}

type effectiveLanguage struct {
	Label         string            `json:"label"`
	NativeName    string            `json:"nativeName"`
	Enabled       bool              `json:"enabled"`
	Direction     string            `json:"direction"`
	Sort          int               `json:"sort"`
	Source        string            `json:"source"`
	PublishStatus string            `json:"publishStatus"`
	Resource      *languageResource `json:"resource"`
}

type effectiveLanguagesConfig struct {
	SchemaVersion          int                          `json:"schemaVersion"`
	FallbackLanguage       string                       `json:"fallbackLanguage"`
	RefreshIntervalSeconds int                          `json:"refreshIntervalSeconds"`
	Languages              map[string]effectiveLanguage `json:"languages"`
}

type languageConfigRecord struct {
	TenantID  string
	Value     storedLanguagesConfig
	Version   int
	UpdatedBy string
	UpdatedAt time.Time
}

type languageDocumentValue struct {
	Content string `json:"content"`
	Source  string `json:"source"`
	Missing bool   `json:"missing"`
}

type languageDocumentItem struct {
	Key    string                           `json:"key"`
	Meta   string                           `json:"meta"`
	Values map[string]languageDocumentValue `json:"values"`
}

func defaultStoredLanguagesConfig() storedLanguagesConfig {
	zhLabel, enLabel := "简体中文", "English"
	zhEnabled, enEnabled := true, true
	ltr := "ltr"
	zhSort, enSort := 1, 2
	return storedLanguagesConfig{
		SchemaVersion:          2,
		FallbackLanguage:       "zh-CN",
		RefreshIntervalSeconds: 21600,
		Languages: map[string]languageOverride{
			"zh-CN": {Label: &zhLabel, NativeName: &zhLabel, Enabled: &zhEnabled, Direction: &ltr, Sort: &zhSort},
			"en-US": {Label: &enLabel, NativeName: &enLabel, Enabled: &enEnabled, Direction: &ltr, Sort: &enSort},
		},
		Resources:       map[string]languageResource{},
		DirtyLanguages:  map[string]bool{},
		FailedLanguages: map[string]string{},
	}
}

func validLanguageCode(code string) bool {
	return languageCodePattern.MatchString(code) && !strings.Contains(code, "_")
}

func applyLanguageOverride(base effectiveLanguage, value languageOverride, source string) effectiveLanguage {
	if value.Label != nil {
		base.Label = strings.TrimSpace(*value.Label)
	}
	if value.NativeName != nil {
		base.NativeName = strings.TrimSpace(*value.NativeName)
	}
	if value.Enabled != nil {
		base.Enabled = *value.Enabled
	}
	if value.Direction != nil {
		base.Direction = strings.TrimSpace(*value.Direction)
	}
	if value.Sort != nil {
		base.Sort = *value.Sort
	}
	base.Source = source
	return base
}

func mergeLanguages(global, tenant storedLanguagesConfig) (effectiveLanguagesConfig, error) {
	result := effectiveLanguagesConfig{SchemaVersion: 2, FallbackLanguage: global.FallbackLanguage, RefreshIntervalSeconds: global.RefreshIntervalSeconds, Languages: map[string]effectiveLanguage{}}
	if result.FallbackLanguage == "" {
		result.FallbackLanguage = "zh-CN"
	}
	if result.RefreshIntervalSeconds == 0 {
		result.RefreshIntervalSeconds = 21600
	}
	for code, value := range global.Languages {
		if !validLanguageCode(code) {
			return result, fmt.Errorf("invalid global language code %q", code)
		}
		item := applyLanguageOverride(effectiveLanguage{Enabled: true, Direction: "ltr", Source: "global", PublishStatus: "draft"}, value, "global")
		if resource, ok := global.Resources[code]; ok {
			copy := resource
			item.Resource, item.PublishStatus = &copy, "published"
		}
		if global.DirtyLanguages[code] {
			item.PublishStatus = "draft"
		}
		if global.FailedLanguages[code] != "" {
			item.PublishStatus = "publish_failed"
		}
		result.Languages[code] = item
	}
	if tenant.FallbackLanguage != "" {
		result.FallbackLanguage = tenant.FallbackLanguage
	}
	if tenant.RefreshIntervalSeconds != 0 {
		result.RefreshIntervalSeconds = tenant.RefreshIntervalSeconds
	}
	for code, value := range tenant.Languages {
		if !validLanguageCode(code) {
			return result, fmt.Errorf("invalid tenant language code %q", code)
		}
		item, exists := result.Languages[code]
		if !exists {
			item = effectiveLanguage{Enabled: true, Direction: "ltr", Source: "tenant", PublishStatus: "draft"}
		}
		result.Languages[code] = applyLanguageOverride(item, value, "tenant")
	}
	for code, resource := range tenant.Resources {
		item, exists := result.Languages[code]
		if !exists {
			continue
		}
		copy := resource
		item.Resource, item.PublishStatus = &copy, "published"
		if tenant.DirtyLanguages[code] {
			item.PublishStatus = "draft"
		}
		if tenant.FailedLanguages[code] != "" {
			item.PublishStatus = "publish_failed"
		}
		result.Languages[code] = item
	}
	if !validLanguageCode(result.FallbackLanguage) {
		return result, errors.New("fallback language must use canonical BCP 47 format")
	}
	if item, ok := result.Languages[result.FallbackLanguage]; !ok || !item.Enabled {
		return result, errors.New("fallback language must be enabled")
	}
	if result.RefreshIntervalSeconds < 300 || result.RefreshIntervalSeconds > 86400 {
		return result, errors.New("refresh interval must be between 300 and 86400 seconds")
	}
	for code, item := range result.Languages {
		if item.Label == "" || item.NativeName == "" || item.Sort < 0 || (item.Direction != "ltr" && item.Direction != "rtl") {
			return result, fmt.Errorf("language %s is incomplete", code)
		}
	}
	return result, nil
}

func (s *server) languageConfigRecords(ctx context.Context, tenant string) (languageConfigRecord, languageConfigRecord, error) {
	global := languageConfigRecord{TenantID: "0", Value: defaultStoredLanguagesConfig()}
	current := languageConfigRecord{TenantID: tenant, Value: storedLanguagesConfig{Languages: map[string]languageOverride{}, Resources: map[string]languageResource{}, DirtyLanguages: map[string]bool{}, FailedLanguages: map[string]string{}}}
	rows, err := s.db.QueryContext(ctx, `SELECT CAST(tenant_id AS CHAR),config_value,version,updated_by,updated_at FROM app_configs WHERE config_key=? AND tenant_id IN (0,?) ORDER BY tenant_id ASC`, languagesConfigKey, tenant)
	if err != nil {
		return global, current, err
	}
	defer rows.Close()
	for rows.Next() {
		var record languageConfigRecord
		var raw []byte
		if err := rows.Scan(&record.TenantID, &raw, &record.Version, &record.UpdatedBy, &record.UpdatedAt); err != nil {
			return global, current, err
		}
		if err := json.Unmarshal(raw, &record.Value); err != nil {
			return global, current, err
		}
		if record.Value.Languages == nil {
			record.Value.Languages = map[string]languageOverride{}
		}
		if record.Value.Resources == nil {
			record.Value.Resources = map[string]languageResource{}
		}
		if record.Value.DirtyLanguages == nil {
			record.Value.DirtyLanguages = map[string]bool{}
		}
		if record.Value.FailedLanguages == nil {
			record.Value.FailedLanguages = map[string]string{}
		}
		if record.TenantID == "0" {
			global = record
		} else {
			current = record
		}
	}
	return global, current, rows.Err()
}

func (s *server) effectiveLanguageSettings(ctx context.Context, tenant string) (effectiveLanguagesConfig, languageConfigRecord, languageConfigRecord, error) {
	global, current, err := s.languageConfigRecords(ctx, tenant)
	if err != nil {
		return effectiveLanguagesConfig{}, global, current, err
	}
	effective, err := mergeLanguages(global.Value, current.Value)
	return effective, global, current, err
}

func (s *server) localizationView(ctx context.Context, tenant string) (gin.H, error) {
	settings, global, current, err := s.effectiveLanguageSettings(ctx, tenant)
	if err != nil {
		return nil, err
	}
	documents, err := s.queryLanguageDocuments(ctx, tenant, settings)
	if err != nil {
		return nil, err
	}
	return gin.H{
		"settings":  settings,
		"documents": gin.H{"items": documents, "total": len(documents)},
		"metadata":  gin.H{"globalVersion": global.Version, "tenantVersion": current.Version, "inherited": current.Version == 0, "updatedBy": current.UpdatedBy, "updatedAt": nullableTime(current.UpdatedAt)},
	}, nil
}

func (s *server) getLocalization(c *gin.Context) {
	view, err := s.localizationView(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, 500, "LOCALIZATION_QUERY_FAILED", "Unable to load localization")
		return
	}
	c.JSON(http.StatusOK, view)
}

func (s *server) queryLanguageDocuments(ctx context.Context, tenant string, settings effectiveLanguagesConfig) ([]languageDocumentItem, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT CAST(tenant_id AS CHAR),lang,`+"`key`"+`,content,meta FROM language_document WHERE tenant_id IN (0,?) AND type=? AND deleted=0 ORDER BY `+"`key`"+`,lang,tenant_id`, tenant, appLanguageType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type rawValue struct{ content, source, meta string }
	byKey := map[string]map[string]rawValue{}
	for rows.Next() {
		var source, language, key, content, meta string
		if err := rows.Scan(&source, &language, &key, &content, &meta); err != nil {
			return nil, err
		}
		if !validLanguageCode(language) {
			return nil, fmt.Errorf("invalid language code %q in language_document", language)
		}
		if byKey[key] == nil {
			byKey[key] = map[string]rawValue{}
		}
		current, exists := byKey[key][language]
		if !exists || source == tenant || current.source == "0" {
			byKey[key][language] = rawValue{content: content, source: source, meta: meta}
		}
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	items := make([]languageDocumentItem, 0, len(keys))
	for _, key := range keys {
		item := languageDocumentItem{Key: key, Values: map[string]languageDocumentValue{}}
		for code := range settings.Languages {
			value, ok := byKey[key][code]
			if ok {
				item.Values[code] = languageDocumentValue{Content: value.content, Source: mapSource(value.source, tenant), Missing: false}
				if item.Meta == "" {
					item.Meta = value.meta
				}
			} else {
				item.Values[code] = languageDocumentValue{Content: "", Source: "missing", Missing: true}
			}
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func mapSource(source, tenant string) string {
	if source == tenant {
		return "tenant"
	}
	return "global"
}

type languageSettingsInput struct {
	SchemaVersion          int    `json:"schemaVersion"`
	FallbackLanguage       string `json:"fallbackLanguage"`
	RefreshIntervalSeconds int    `json:"refreshIntervalSeconds"`
	Languages              map[string]struct {
		Label      string `json:"label"`
		NativeName string `json:"nativeName"`
		Enabled    bool   `json:"enabled"`
		Direction  string `json:"direction"`
		Sort       int    `json:"sort"`
	} `json:"languages"`
}

func (s *server) updateLocalizationLanguages(c *gin.Context) {
	var body struct {
		Settings        languageSettingsInput `json:"settings"`
		ExpectedVersion int                   `json:"expectedVersion"`
		Reason          string                `json:"reason"`
	}
	if decode(c, &body) != nil || body.Settings.SchemaVersion != 2 || body.ExpectedVersion < 0 || len(strings.TrimSpace(body.Reason)) < 3 {
		problem(c, 400, "INVALID_LANGUAGE_SETTINGS", "settings, expectedVersion and reason are required")
		return
	}
	global, current, err := s.languageConfigRecords(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, 500, "LOCALIZATION_QUERY_FAILED", "Unable to load language settings")
		return
	}
	if current.Version != body.ExpectedVersion {
		problem(c, 409, "STALE_LANGUAGE_SETTINGS", "Language settings changed since they were loaded")
		return
	}
	desired := storedLanguagesConfig{SchemaVersion: 2, FallbackLanguage: body.Settings.FallbackLanguage, RefreshIntervalSeconds: body.Settings.RefreshIntervalSeconds, Languages: map[string]languageOverride{}}
	for code, input := range body.Settings.Languages {
		label, nativeName, enabled, direction, sortValue := strings.TrimSpace(input.Label), strings.TrimSpace(input.NativeName), input.Enabled, strings.TrimSpace(input.Direction), input.Sort
		desired.Languages[code] = languageOverride{Label: &label, NativeName: &nativeName, Enabled: &enabled, Direction: &direction, Sort: &sortValue}
	}
	if _, err := mergeLanguages(desired, storedLanguagesConfig{}); err != nil {
		problem(c, 422, "INVALID_LANGUAGE_SETTINGS", err.Error())
		return
	}
	overrides := diffLanguageSettings(global.Value, desired)
	overrides.Resources = current.Value.Resources
	overrides.DirtyLanguages = current.Value.DirtyLanguages
	overrides.FailedLanguages = current.Value.FailedLanguages
	raw, _ := json.Marshal(overrides)
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, 500, "LANGUAGE_SETTINGS_SAVE_FAILED", "Unable to save language settings")
		return
	}
	defer tx.Rollback()
	newVersion := current.Version + 1
	var result sql.Result
	if current.Version == 0 {
		result, err = tx.ExecContext(c.Request.Context(), `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,?,?,?)`, tenantID(c), languagesConfigKey, raw, 1, actor(c), now)
		newVersion = 1
	} else {
		result, err = tx.ExecContext(c.Request.Context(), `UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`, raw, actor(c), now, tenantID(c), languagesConfigKey, current.Version)
	}
	if err != nil {
		problem(c, 500, "LANGUAGE_SETTINGS_SAVE_FAILED", "Unable to save language settings")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, 409, "STALE_LANGUAGE_SETTINGS", "Language settings changed since they were loaded")
		return
	}
	event := newAudit(tenantID(c), actor(c), "localization_languages_update", "localization", languagesConfigKey, body.Reason, requestID(c), map[string]any{"tenantVersion": newVersion, "languageCount": len(body.Settings.Languages)})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, 500, "LANGUAGE_SETTINGS_SAVE_FAILED", "Unable to save language settings")
		return
	}
	view, _ := s.localizationView(c.Request.Context(), tenantID(c))
	c.JSON(http.StatusOK, view)
}

func diffLanguageSettings(global, desired storedLanguagesConfig) storedLanguagesConfig {
	result := storedLanguagesConfig{SchemaVersion: 2, Languages: map[string]languageOverride{}, Resources: map[string]languageResource{}}
	if desired.FallbackLanguage != global.FallbackLanguage {
		result.FallbackLanguage = desired.FallbackLanguage
	}
	if desired.RefreshIntervalSeconds != global.RefreshIntervalSeconds {
		result.RefreshIntervalSeconds = desired.RefreshIntervalSeconds
	}
	for code, desiredValue := range desired.Languages {
		globalValue, exists := global.Languages[code]
		if !exists {
			result.Languages[code] = desiredValue
			continue
		}
		delta := languageOverride{}
		if stringValue(desiredValue.Label) != stringValue(globalValue.Label) {
			delta.Label = desiredValue.Label
		}
		if stringValue(desiredValue.NativeName) != stringValue(globalValue.NativeName) {
			delta.NativeName = desiredValue.NativeName
		}
		if boolValue(desiredValue.Enabled, true) != boolValue(globalValue.Enabled, true) {
			delta.Enabled = desiredValue.Enabled
		}
		if stringValue(desiredValue.Direction) != stringValue(globalValue.Direction) {
			delta.Direction = desiredValue.Direction
		}
		if intValue(desiredValue.Sort) != intValue(globalValue.Sort) {
			delta.Sort = desiredValue.Sort
		}
		if delta.Label != nil || delta.NativeName != nil || delta.Enabled != nil || delta.Direction != nil || delta.Sort != nil {
			result.Languages[code] = delta
		}
	}
	return result
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
func boolValue(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}
func intValue(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}

func (s *server) updateLocalizationDocuments(c *gin.Context) {
	var body struct {
		Documents []struct {
			Key    string             `json:"key"`
			Meta   string             `json:"meta"`
			Values map[string]*string `json:"values"`
		} `json:"documents"`
		Reason string `json:"reason"`
	}
	if decode(c, &body) != nil || len(strings.TrimSpace(body.Reason)) < 3 || len(body.Documents) == 0 {
		problem(c, 400, "INVALID_LANGUAGE_DOCUMENTS", "documents and reason are required")
		return
	}
	settings, _, _, err := s.effectiveLanguageSettings(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, 500, "LOCALIZATION_QUERY_FAILED", "Unable to load language settings")
		return
	}
	_, currentConfig, err := s.languageConfigRecords(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, 500, "LOCALIZATION_QUERY_FAILED", "Unable to load language settings")
		return
	}
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, 500, "LANGUAGE_DOCUMENT_SAVE_FAILED", "Unable to save language documents")
		return
	}
	defer tx.Rollback()
	changed := 0
	dirtyLanguages := map[string]bool{}
	for _, document := range body.Documents {
		key := strings.TrimSpace(document.Key)
		if !messageKeyPattern.MatchString(key) || len(document.Meta) > 255 {
			problem(c, 422, "INVALID_LANGUAGE_DOCUMENTS", "Document key or metadata is invalid")
			return
		}
		for code, content := range document.Values {
			if _, ok := settings.Languages[code]; !ok || !validLanguageCode(code) {
				problem(c, 422, "INVALID_LANGUAGE_DOCUMENTS", "Document language is not configured")
				return
			}
			if content == nil {
				_, err = tx.ExecContext(c.Request.Context(), `UPDATE language_document SET deleted=1,mtime=? WHERE tenant_id=? AND lang=? AND `+"`key`"+`=? AND type=?`, time.Now().UTC(), tenantID(c), code, key, appLanguageType)
			} else {
				value := strings.TrimSpace(*content)
				if value == "" || utf8.RuneCountInString(value) > 5000 {
					problem(c, 422, "INVALID_LANGUAGE_DOCUMENTS", "Document content cannot be empty or exceed 5000 characters")
					return
				}
				_, err = tx.ExecContext(c.Request.Context(), `INSERT INTO language_document(lang,`+"`key`"+`,content,meta,type,edit,tenant_id,ctime,mtime,deleted) VALUES(?,?,?,?,?,1,?,?,?,0) ON DUPLICATE KEY UPDATE content=VALUES(content),meta=VALUES(meta),edit=1,mtime=VALUES(mtime),deleted=0`, code, key, value, strings.TrimSpace(document.Meta), appLanguageType, tenantID(c), time.Now().UTC(), time.Now().UTC())
			}
			dirtyLanguages[code] = true
			if err != nil {
				problem(c, 500, "LANGUAGE_DOCUMENT_SAVE_FAILED", "Unable to save language documents")
				return
			}
			changed++
		}
	}
	if err := markLocalizationDirtyTx(c.Request.Context(), tx, tenantID(c), currentConfig, dirtyLanguages); err != nil {
		problem(c, 500, "LANGUAGE_DOCUMENT_SAVE_FAILED", "Unable to mark localization draft")
		return
	}
	event := newAudit(tenantID(c), actor(c), "localization_documents_update", "localization", "documents", body.Reason, requestID(c), map[string]any{"changedValues": changed})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, 500, "LANGUAGE_DOCUMENT_SAVE_FAILED", "Unable to save language documents")
		return
	}
	view, _ := s.localizationView(c.Request.Context(), tenantID(c))
	c.JSON(http.StatusOK, view)
}

func (s *server) publishLocalization(c *gin.Context) {
	var body struct {
		Languages []string `json:"languages"`
		Reason    string   `json:"reason"`
	}
	if decode(c, &body) != nil || len(strings.TrimSpace(body.Reason)) < 3 {
		problem(c, 400, "INVALID_LOCALIZATION_PUBLISH", "reason is required")
		return
	}
	settings, _, current, err := s.effectiveLanguageSettings(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, 500, "LOCALIZATION_QUERY_FAILED", "Unable to load localization")
		return
	}
	selected := body.Languages
	if len(selected) == 0 {
		for code, item := range settings.Languages {
			if item.Enabled {
				selected = append(selected, code)
			}
		}
		sort.Strings(selected)
	}
	client, objectPrefix, err := s.storageClientForTenant(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, 503, "STORAGE_UNAVAILABLE", "Localization storage is not configured")
		return
	}
	version := time.Now().UTC().Format("060102150405")
	resources := cloneResources(current.Value.Resources)
	for _, code := range selected {
		item, ok := settings.Languages[code]
		if !ok || !item.Enabled || !validLanguageCode(code) {
			problem(c, 422, "INVALID_LOCALIZATION_PUBLISH", "Every published language must be configured and enabled")
			return
		}
		messages, err := s.compiledMessages(c.Request.Context(), tenantID(c), code, settings.FallbackLanguage)
		if err != nil {
			s.markLocalizationPublishFailure(c.Request.Context(), tenantID(c), current, code, err.Error())
			problem(c, 500, "LOCALIZATION_BUILD_FAILED", "Unable to build localization document")
			return
		}
		payload := struct {
			SchemaVersion int               `json:"schemaVersion"`
			TenantID      string            `json:"tenantId"`
			LanguageCode  string            `json:"languageCode"`
			Version       string            `json:"version"`
			GeneratedAt   string            `json:"generatedAt"`
			Messages      map[string]string `json:"messages"`
		}{1, tenantID(c), code, version, iso(time.Now().UTC()), messages}
		raw, _ := json.Marshal(payload)
		hash := sha256.Sum256(raw)
		objectKey := strings.TrimLeft(path.Join(objectPrefix, "localization", tenantID(c), code, tenantID(c)+"_"+version+"_"+code+".json"), "/")
		if err := client.Put(c.Request.Context(), objectKey, bytes.NewReader(raw), int64(len(raw)), "application/json; charset=utf-8"); err != nil {
			s.markLocalizationPublishFailure(c.Request.Context(), tenantID(c), current, code, err.Error())
			problem(c, 502, "LOCALIZATION_UPLOAD_FAILED", "Unable to upload localization document")
			return
		}
		size, _, err := client.Head(c.Request.Context(), objectKey)
		if err != nil || size != int64(len(raw)) {
			s.markLocalizationPublishFailure(c.Request.Context(), tenantID(c), current, code, "uploaded localization resource could not be verified")
			problem(c, 502, "LOCALIZATION_UPLOAD_FAILED", "Uploaded localization document could not be verified")
			return
		}
		resources[code] = languageResource{Version: version, ObjectKey: objectKey, FileURL: "/v1/mobile/languages/" + code + "/document?v=" + version, SHA256: hex.EncodeToString(hash[:]), Size: size, PublishedAt: iso(time.Now().UTC())}
	}
	if err := s.savePublishedResources(c.Request.Context(), tenantID(c), current, resources, selected, actor(c), body.Reason, requestID(c), version); err != nil {
		problem(c, 409, "LOCALIZATION_PUBLISH_CONFLICT", "Language settings changed while publishing; retry")
		return
	}
	view, _ := s.localizationView(c.Request.Context(), tenantID(c))
	c.JSON(http.StatusOK, gin.H{"version": version, "languages": selected, "localization": view})
}

func cloneResources(source map[string]languageResource) map[string]languageResource {
	result := map[string]languageResource{}
	for key, value := range source {
		result[key] = value
	}
	return result
}

func (s *server) savePublishedResources(ctx context.Context, tenant string, current languageConfigRecord, resources map[string]languageResource, published []string, updatedBy, reason, requestID, publishVersion string) error {
	value := current.Value
	if value.Languages == nil {
		value.Languages = map[string]languageOverride{}
	}
	value.SchemaVersion, value.Resources = 2, resources
	if value.DirtyLanguages == nil {
		value.DirtyLanguages = map[string]bool{}
	}
	if value.FailedLanguages == nil {
		value.FailedLanguages = map[string]string{}
	}
	for _, code := range published {
		delete(value.DirtyLanguages, code)
		delete(value.FailedLanguages, code)
	}
	raw, _ := json.Marshal(value)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	if current.Version == 0 {
		if _, err = tx.ExecContext(ctx, `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,?,?,?)`, tenant, languagesConfigKey, raw, 1, updatedBy, now); err != nil {
			return err
		}
	} else {
		result, updateErr := tx.ExecContext(ctx, `UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`, raw, updatedBy, now, tenant, languagesConfigKey, current.Version)
		if updateErr != nil {
			return updateErr
		}
		affected, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return rowsErr
		}
		if affected != 1 {
			return errors.New("stale language config")
		}
	}
	event := newAudit(tenant, updatedBy, "localization_publish", "localization", publishVersion, reason, requestID, map[string]any{"languages": published, "version": publishVersion})
	if err := insertAudit(ctx, tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func markLocalizationDirtyTx(ctx context.Context, tx *sql.Tx, tenant string, current languageConfigRecord, languages map[string]bool) error {
	if len(languages) == 0 {
		return nil
	}
	if current.Value.DirtyLanguages == nil {
		current.Value.DirtyLanguages = map[string]bool{}
	}
	if current.Value.FailedLanguages == nil {
		current.Value.FailedLanguages = map[string]string{}
	}
	for code := range languages {
		current.Value.DirtyLanguages[code] = true
		delete(current.Value.FailedLanguages, code)
	}
	raw, _ := json.Marshal(current.Value)
	if current.Version == 0 {
		_, err := tx.ExecContext(ctx, `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,?,?,?)`, tenant, languagesConfigKey, raw, 1, "system-localization", time.Now().UTC())
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`, raw, "system-localization", time.Now().UTC(), tenant, languagesConfigKey, current.Version)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return errors.New("stale language config")
	}
	return nil
}

func (s *server) markLocalizationPublishFailure(ctx context.Context, tenant string, current languageConfigRecord, code, message string) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			_, latest, err := s.languageConfigRecords(ctx, tenant)
			if err != nil {
				slog.Error("localization publish failure state could not be reloaded", "tenant", tenant, "language", code, "error", err)
				return
			}
			current = latest
		}
		if current.Value.DirtyLanguages == nil {
			current.Value.DirtyLanguages = map[string]bool{}
		}
		if current.Value.FailedLanguages == nil {
			current.Value.FailedLanguages = map[string]string{}
		}
		current.Value.DirtyLanguages[code] = true
		current.Value.FailedLanguages[code] = message
		if err := s.saveLanguageConfigState(ctx, tenant, current); err == nil {
			return
		} else {
			lastErr = err
		}
	}
	slog.Error("localization publish failure state could not be saved", "tenant", tenant, "language", code, "error", lastErr)
}

func (s *server) saveLanguageConfigState(ctx context.Context, tenant string, current languageConfigRecord) error {
	value := current.Value
	raw, _ := json.Marshal(value)
	if current.Version == 0 {
		_, err := s.db.ExecContext(ctx, `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,?,?,?)`, tenant, languagesConfigKey, raw, 1, "system-localization", time.Now().UTC())
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`, raw, "system-localization", time.Now().UTC(), tenant, languagesConfigKey, current.Version)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return errors.New("stale language config")
	}
	return nil
}

func (s *server) compiledMessages(ctx context.Context, tenant, language, fallback string) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT CAST(tenant_id AS CHAR),lang,`+"`key`"+`,content FROM language_document WHERE tenant_id IN (0,?) AND lang IN (?,?) AND type=? AND deleted=0 ORDER BY tenant_id ASC`, tenant, language, fallback, appLanguageType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	targetGlobal, targetTenant, fallbackGlobal, fallbackTenant := map[string]string{}, map[string]string{}, map[string]string{}, map[string]string{}
	keys := map[string]struct{}{}
	for rows.Next() {
		var source, code, key, content string
		if err := rows.Scan(&source, &code, &key, &content); err != nil {
			return nil, err
		}
		keys[key] = struct{}{}
		target := targetGlobal
		if code == language && source == tenant {
			target = targetTenant
		} else if code == fallback && source == "0" {
			target = fallbackGlobal
		} else if code == fallback && source == tenant {
			target = fallbackTenant
		}
		target[key] = content
	}
	result := map[string]string{}
	for key := range keys {
		if value := targetTenant[key]; value != "" {
			result[key] = value
		} else if value := targetGlobal[key]; value != "" {
			result[key] = value
		} else if value := fallbackTenant[key]; value != "" {
			result[key] = value
		} else if value := fallbackGlobal[key]; value != "" {
			result[key] = value
		} else {
			result[key] = key
		}
	}
	return result, rows.Err()
}

func (s *server) mobileLanguageDocument(c *gin.Context) {
	tenant, err := s.tenant.resolve(c.Request.Context(), c.Request.Host)
	if err != nil {
		problem(c, 404, "TENANT_NOT_FOUND", "Tenant not found")
		return
	}
	code := c.Param("languageCode")
	if !validLanguageCode(code) {
		problem(c, 400, "INVALID_LANGUAGE_CODE", "Language code must use canonical BCP 47 format")
		return
	}
	settings, global, current, err := s.effectiveLanguageSettings(c.Request.Context(), tenant.ID)
	if err != nil {
		problem(c, 503, "LOCALIZATION_UNAVAILABLE", "Localization is unavailable")
		return
	}
	item, ok := settings.Languages[code]
	if !ok || !item.Enabled || item.Resource == nil {
		problem(c, 404, "LANGUAGE_RESOURCE_NOT_FOUND", "Published language resource not found")
		return
	}
	resource := *item.Resource
	resourceTenant := "0"
	if _, exists := current.Value.Resources[code]; exists {
		resourceTenant = tenant.ID
	} else if _, exists := global.Value.Resources[code]; !exists {
		problem(c, 404, "LANGUAGE_RESOURCE_NOT_FOUND", "Published language resource not found")
		return
	}
	if match := strings.Trim(c.GetHeader("If-None-Match"), `"`); match == resource.SHA256 {
		c.Status(http.StatusNotModified)
		return
	}
	client, _, err := s.storageClientForTenant(c.Request.Context(), resourceTenant)
	if err != nil {
		problem(c, 503, "STORAGE_UNAVAILABLE", "Localization storage is unavailable")
		return
	}
	body, err := client.Get(c.Request.Context(), resource.ObjectKey)
	if err != nil {
		problem(c, 502, "LANGUAGE_RESOURCE_READ_FAILED", "Unable to read language resource")
		return
	}
	defer body.Close()
	c.Header("Content-Type", "application/json; charset=utf-8")
	c.Header("Cache-Control", "public, max-age=300")
	c.Header("ETag", `"`+resource.SHA256+`"`)
	c.Header("X-Content-SHA256", resource.SHA256)
	c.Header("Content-Length", fmt.Sprint(resource.Size))
	_, _ = io.Copy(c.Writer, body)
}
