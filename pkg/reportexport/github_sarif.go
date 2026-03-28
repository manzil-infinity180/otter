package reportexport

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// GitHubSARIFUploadRequest configures a SARIF upload to GitHub Code Scanning.
type GitHubSARIFUploadRequest struct {
	Repository string // "owner/repo"
	Ref        string // "refs/heads/main"
	CommitSHA  string // optional, defaults to HEAD of Ref
	Token      string // GitHub PAT or installation token
	SARIF      []byte // raw SARIF JSON
}

// GitHubSARIFUploadResponse is the response from the GitHub upload.
type GitHubSARIFUploadResponse struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// UploadSARIFToGitHub pushes a SARIF report to GitHub's Code Scanning API.
// See: https://docs.github.com/en/rest/code-scanning/code-scanning#upload-an-analysis-as-sarif-data
func UploadSARIFToGitHub(ctx context.Context, req GitHubSARIFUploadRequest) (*GitHubSARIFUploadResponse, error) {
	if req.Repository == "" {
		return nil, fmt.Errorf("github_sarif: repository is required")
	}
	if req.Ref == "" {
		return nil, fmt.Errorf("github_sarif: ref is required")
	}
	if req.Token == "" {
		return nil, fmt.Errorf("github_sarif: token is required")
	}
	if len(req.SARIF) == 0 {
		return nil, fmt.Errorf("github_sarif: SARIF data is empty")
	}

	// GitHub requires base64-encoded gzip-compressed SARIF
	compressed, err := gzipAndEncode(req.SARIF)
	if err != nil {
		return nil, fmt.Errorf("github_sarif: compress SARIF: %w", err)
	}

	body := map[string]string{
		"sarif":      compressed,
		"ref":        req.Ref,
		"tool_name":  "otter",
	}
	if req.CommitSHA != "" {
		body["commit_sha"] = req.CommitSHA
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("github_sarif: marshal payload: %w", err)
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/code-scanning/sarifs", req.Repository)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("github_sarif: create request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/vnd.github+json")
	httpReq.Header.Set("Authorization", "Bearer "+req.Token)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "Otter-SARIF-Uploader/1.0")
	httpReq.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("github_sarif: upload request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github_sarif: upload failed (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result GitHubSARIFUploadResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("github_sarif: parse response: %w", err)
	}

	return &result, nil
}

func gzipAndEncode(data []byte) (string, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		return "", err
	}
	if err := gz.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
