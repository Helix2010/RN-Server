package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type claimedJob struct {
	ID                   string `json:"id"`
	TenantSlug           string `json:"tenantSlug"`
	Platform             string `json:"platform"`
	GitRef               string `json:"gitRef"`
	Version              string `json:"version"`
	BuildNumber          int    `json:"buildNumber"`
	OTACertificatePEM    string `json:"otaCertificatePem"`
	OTACertificateSHA256 string `json:"otaCertificateSha256"`
}

type client struct {
	cfg  config
	http *http.Client
}

func newClient(cfg config) *client {
	return &client{cfg: cfg, http: &http.Client{Timeout: 30 * time.Second}}
}

func (c *client) post(ctx context.Context, path string, body any, out any) (int, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reader = bytes.NewReader(raw)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Server+path, reader)
	if err != nil {
		return 0, err
	}
	request.Header.Set("content-type", "application/json")
	request.Header.Set("x-build-agent-token", c.cfg.Token)
	response, err := c.http.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode >= 400 {
		// 错误正文里不会有机密，但也不需要原样带出去——只留状态码和一小段
		return response.StatusCode, fmt.Errorf("%s returned %d: %s", path, response.StatusCode, truncate(string(payload), 300))
	}
	if out != nil && len(payload) > 0 {
		if err := json.Unmarshal(payload, out); err != nil {
			return response.StatusCode, fmt.Errorf("%s returned a body we cannot read: %w", path, err)
		}
	}
	return response.StatusCode, nil
}

// claim 返回 (任务, 有没有任务, 错误)。队列空时服务端给 204。
func (c *client) claim(ctx context.Context) (claimedJob, bool, error) {
	var job claimedJob
	status, err := c.post(ctx, "/v1/build-agent/claim", map[string]any{
		"agent": c.cfg.Name, "platforms": c.cfg.Platforms,
	}, &job)
	if err != nil {
		return job, false, err
	}
	if status == http.StatusNoContent || job.ID == "" {
		return job, false, nil
	}
	return job, true, nil
}

func (c *client) heartbeat(ctx context.Context, id string, logTail []string) error {
	_, err := c.post(ctx, "/v1/build-agent/jobs/"+id+"/heartbeat", map[string]any{"logTail": logTail}, nil)
	return err
}

func (c *client) complete(ctx context.Context, id, commit, digest, releaseID string, logTail []string) error {
	_, err := c.post(ctx, "/v1/build-agent/jobs/"+id+"/complete", map[string]any{
		"commitSha": commit, "artifactSha256": digest, "releaseId": releaseID, "logTail": logTail,
	}, nil)
	return err
}

func (c *client) fail(ctx context.Context, id, reason, commit string, logTail []string) error {
	_, err := c.post(ctx, "/v1/build-agent/jobs/"+id+"/fail", map[string]any{
		"failureReason": reason, "commitSha": commit, "logTail": logTail,
	}, nil)
	return err
}

func truncate(text string, max int) string {
	if len(text) <= max {
		return text
	}
	return text[:max] + "…"
}
