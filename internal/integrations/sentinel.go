package integrations

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Sentinel posts findings to a Log Analytics workspace via the HTTP Data Collector API
// (custom table <LogType>_CL, default CloudPosture_CL) for Microsoft Sentinel.
type Sentinel struct {
	WorkspaceID string
	SharedKey   string
	LogType     string
	Endpoint    string
	now         func() time.Time
}

func NewSentinel(workspaceID, sharedKey string) *Sentinel {
	return &Sentinel{WorkspaceID: workspaceID, SharedKey: sharedKey, LogType: "CloudPosture"}
}

func (s *Sentinel) Name() string { return "sentinel" }

// SentinelSignature computes the Data Collector API SharedKey authorization header value.
func SentinelSignature(workspaceID, sharedKey, date string, contentLength int) (string, error) {
	key, err := base64.StdEncoding.DecodeString(sharedKey)
	if err != nil {
		return "", fmt.Errorf("sentinel shared key is not valid base64: %w", err)
	}
	toSign := "POST\n" + strconv.Itoa(contentLength) + "\napplication/json\nx-ms-date:" + date + "\n/api/logs"
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(toSign))
	return "SharedKey " + workspaceID + ":" + base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (s *Sentinel) Deliver(ctx context.Context, f model.Finding, paths []model.AttackPath) (string, error) {
	if s.WorkspaceID == "" || s.SharedKey == "" {
		return "", fmt.Errorf("sentinel requires workspace id and shared key (SENTINEL_WORKSPACE_ID, SENTINEL_SHARED_KEY)")
	}
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	ts := now().UTC()
	rec := Event(f, paths)
	rec["TimeGenerated"] = ts.Format(time.RFC3339)
	body, err := json.Marshal([]map[string]any{rec})
	if err != nil {
		return "", err
	}
	date := ts.Format(http.TimeFormat)
	auth, err := SentinelSignature(s.WorkspaceID, s.SharedKey, date, len(body))
	if err != nil {
		return "", err
	}
	endpoint := firstNonEmpty(s.Endpoint, "https://"+s.WorkspaceID+".ods.opinsights.azure.com")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(endpoint, "/")+"/api/logs?api-version=2016-04-01", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Log-Type", firstNonEmpty(s.LogType, "CloudPosture"))
	req.Header.Set("x-ms-date", date)
	req.Header.Set("time-generated-field", "TimeGenerated")
	req.Header.Set("Authorization", auth)
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("sentinel data collector responded %d: %s", resp.StatusCode, truncate(string(data), 200))
	}
	return "sentinel", nil
}
