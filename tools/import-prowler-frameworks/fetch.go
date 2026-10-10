package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Overridable in tests.
var (
	apiBase = "https://api.github.com"
	rawBase = "https://raw.githubusercontent.com"
	client  = &http.Client{Timeout: 60 * time.Second}
)

const maxFileBytes = 64 << 20

func get(url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "nimbus-import-prowler-frameworks")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxFileBytes))
}

// resolveTag returns the commit sha a tag points at (dereferencing annotated tags).
func resolveTag(ref string) (string, error) {
	var r struct {
		Object struct {
			SHA  string `json:"sha"`
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"object"`
	}
	data, err := get(apiBase + "/repos/prowler-cloud/prowler/git/ref/tags/" + ref)
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return "", err
	}
	if r.Object.Type == "tag" {
		data, err := get(apiBase + "/repos/prowler-cloud/prowler/git/tags/" + r.Object.SHA)
		if err != nil {
			return "", err
		}
		if err := json.Unmarshal(data, &r); err != nil {
			return "", err
		}
	}
	if r.Object.SHA == "" {
		return "", fmt.Errorf("tag %s: no sha in API response", ref)
	}
	return r.Object.SHA, nil
}

// download fetches every prowler/compliance/**.json at the pinned commit.
func download(ref, sha string, shaOverridden bool) (map[string][]byte, error) {
	if !shaOverridden {
		got, err := resolveTag(ref)
		if err != nil {
			return nil, err
		}
		if got != sha {
			return nil, fmt.Errorf("tag %s resolves to %s, not the pinned %s; review the new release and pass --sha %s to accept it", ref, got, sha, got)
		}
	}
	data, err := get(apiBase + "/repos/prowler-cloud/prowler/git/trees/" + sha + "?recursive=1")
	if err != nil {
		return nil, err
	}
	var tree struct {
		Truncated bool `json:"truncated"`
		Tree      []struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"tree"`
	}
	if err := json.Unmarshal(data, &tree); err != nil {
		return nil, err
	}
	if tree.Truncated {
		return nil, fmt.Errorf("tree listing for %s is truncated", sha)
	}
	const prefix = "prowler/compliance/"
	files := map[string][]byte{}
	for _, e := range tree.Tree {
		if e.Type != "blob" || !strings.HasPrefix(e.Path, prefix) || !strings.HasSuffix(e.Path, ".json") {
			continue
		}
		body, err := get(rawBase + "/prowler-cloud/prowler/" + sha + "/" + e.Path)
		if err != nil {
			return nil, err
		}
		files[strings.TrimPrefix(e.Path, prefix)] = body
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no framework JSON under %s at %s", prefix, sha)
	}
	return files, nil
}
