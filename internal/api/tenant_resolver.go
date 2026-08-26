package api

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	tenantCacheTTL     = 60 * time.Second
	negativeCacheTTL   = 5 * time.Second
	maxTenantCacheSize = 5000
)

type tenantRecord struct {
	ID        string `json:"id"`
	Slug      string `json:"slug"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

type tenantCacheEntry struct {
	tenant  tenantRecord
	expires time.Time
	missing bool
}

// tenantResolver keeps domain lookup out of business handlers. MySQL remains
// the source of truth; this cache is only a bounded, short-lived accelerator.
type tenantResolver struct {
	db      *sql.DB
	mu      sync.Mutex
	entries map[string]tenantCacheEntry
}

func newTenantResolver(db *sql.DB) *tenantResolver {
	return &tenantResolver{db: db, entries: make(map[string]tenantCacheEntry)}
}

func (r *tenantResolver) resolve(ctx context.Context, rawHost string) (tenantRecord, error) {
	host, err := normalizeHost(rawHost)
	if err != nil {
		return tenantRecord{}, err
	}
	now := time.Now()
	r.mu.Lock()
	if item, ok := r.entries[host]; ok && now.Before(item.expires) {
		r.mu.Unlock()
		if item.missing {
			return tenantRecord{}, sql.ErrNoRows
		}
		return item.tenant, nil
	}
	r.mu.Unlock()

	var item tenantRecord
	var created, updated time.Time
	err = r.db.QueryRowContext(ctx, `
		SELECT CAST(t.id AS CHAR), t.slug, t.slug,
		       CASE WHEN (CAST(t.status AS UNSIGNED)=1 OR t.status='active') AND t.deleted=0
		                  AND CURRENT_DATE >= t.start_date
		                  AND CURRENT_DATE <= t.expiry_date
		            THEN 'active' ELSE 'disabled' END,
		       t.created_at, t.updated_at
		FROM tenant_domain d
		JOIN tenants t ON t.id=d.tenant_id
		WHERE LOWER(TRIM(TRAILING '.' FROM d.domain))=?
		  AND d.status='active' AND d.deleted=0
		  AND (CAST(t.status AS UNSIGNED)=1 OR t.status='active') AND t.deleted=0
		  AND CURRENT_DATE >= t.start_date
		  AND CURRENT_DATE <= t.expiry_date
		LIMIT 1`, host).Scan(&item.ID, &item.Slug, &item.Name, &item.Status, &created, &updated)
	if err == nil {
		item.CreatedAt, item.UpdatedAt = iso(created), iso(updated)
		r.put(host, tenantCacheEntry{tenant: item, expires: now.Add(tenantCacheTTL)})
		return item, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		r.put(host, tenantCacheEntry{missing: true, expires: now.Add(negativeCacheTTL)})
	}
	return tenantRecord{}, err
}

func (r *tenantResolver) invalidate(host string) {
	if normalized, err := normalizeHost(host); err == nil {
		r.mu.Lock()
		delete(r.entries, normalized)
		r.mu.Unlock()
	}
}

func (r *tenantResolver) invalidateTenant(id string) {
	r.mu.Lock()
	for host, entry := range r.entries {
		if entry.tenant.ID == id {
			delete(r.entries, host)
		}
	}
	r.mu.Unlock()
}

func (r *tenantResolver) put(host string, entry tenantCacheEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.entries) >= maxTenantCacheSize {
		for key := range r.entries {
			delete(r.entries, key)
			break
		}
	}
	r.entries[host] = entry
}

func normalizeHost(raw string) (string, error) {
	host := strings.ToLower(strings.TrimSpace(raw))
	if host == "" {
		return "", errors.New("request host is empty")
	}
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	} else if strings.Count(host, ":") == 1 {
		if parsed, _, splitErr := net.SplitHostPort(host + ":443"); splitErr == nil {
			host = parsed
		}
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " /\\\t\r\n") {
		return "", errors.New("invalid request host")
	}
	return host, nil
}
