package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.ibm.com/soub4i/gh-relay/internal/filter"
	"github.ibm.com/soub4i/gh-relay/internal/github"
	"github.ibm.com/soub4i/gh-relay/internal/session"
)

const (
	shaMain   = "1111111111111111111111111111111111111111"
	shaEnv    = "2222222222222222222222222222222222222222"
	shaDocs   = "3333333333333333333333333333333333333333"
	shaSecret = "4444444444444444444444444444444444444444"
)

func TestTreeExcludesDeniedFiles(t *testing.T) {
	tree := testTree()
	srv, _ := newTestServer(t, mustFilter(t, "", ".env,secrets/**"), tree)

	rr := apiRequest(srv, "/api/tree?branch=main")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/tree status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	got := decodeTree(t, rr)
	assertPathPresent(t, got, "src/main.go")
	assertPathAbsent(t, got, ".env")
	assertPathAbsent(t, got, "secrets")
	assertPathAbsent(t, got, "secrets/prod.yml")
}

func TestTreeKeepsParentDirectoriesForAllowedDescendants(t *testing.T) {
	tree := &github.Tree{Tree: []github.TreeEntry{
		{Path: "docs", Type: "tree"},
		{Path: "docs/guide", Type: "tree"},
		{Path: "docs/guide/intro.md", Type: "blob", SHA: shaDocs},
		{Path: "docs/private.md", Type: "blob", SHA: shaSecret},
		{Path: "src", Type: "tree"},
		{Path: "src/main.go", Type: "blob", SHA: shaMain},
	}}
	srv, _ := newTestServer(t, mustFilter(t, "docs/guide/intro.md", ""), tree)

	rr := apiRequest(srv, "/api/tree?branch=main")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/tree status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	got := decodeTree(t, rr)
	assertPathPresent(t, got, "docs")
	assertPathPresent(t, got, "docs/guide")
	assertPathPresent(t, got, "docs/guide/intro.md")
	assertPathAbsent(t, got, "docs/private.md")
	assertPathAbsent(t, got, "src")
	assertPathAbsent(t, got, "src/main.go")
}

func TestBlobRejectsDeniedPathWhenFiltered(t *testing.T) {
	srv, fake := newTestServer(t, mustFilter(t, "", ".env"), testTree())

	rr := apiRequest(srv, fmt.Sprintf("/api/blob?branch=main&sha=%s&path=.env", shaEnv))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("GET /api/blob status = %d, want %d", rr.Code, http.StatusNotFound)
	}
	if fake.getBlobCalls != 0 {
		t.Fatalf("GetBlob calls = %d, want 0", fake.getBlobCalls)
	}
}

func TestBlobRejectsSHAPathMismatchWhenFiltered(t *testing.T) {
	srv, fake := newTestServer(t, mustFilter(t, "src/**", ""), testTree())

	rr := apiRequest(srv, fmt.Sprintf("/api/blob?branch=main&sha=%s&path=src/main.go", shaDocs))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("GET /api/blob status = %d, want %d", rr.Code, http.StatusNotFound)
	}
	if fake.getBlobCalls != 0 {
		t.Fatalf("GetBlob calls = %d, want 0", fake.getBlobCalls)
	}
}

func TestBlobRequiresPathAndBranchWhenFiltered(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{name: "missing path", url: fmt.Sprintf("/api/blob?branch=main&sha=%s", shaMain)},
		{name: "missing branch", url: fmt.Sprintf("/api/blob?sha=%s&path=src/main.go", shaMain)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, fake := newTestServer(t, mustFilter(t, "src/**", ""), testTree())

			rr := apiRequest(srv, tt.url)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("GET /api/blob status = %d, want %d", rr.Code, http.StatusBadRequest)
			}
			if fake.getBlobCalls != 0 {
				t.Fatalf("GetBlob calls = %d, want 0", fake.getBlobCalls)
			}
		})
	}
}

func newTestServer(t *testing.T, policy *filter.Policy, tree *github.Tree) (*Server, *fakeGitHub) {
	t.Helper()
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })

	fake := &fakeGitHub{
		trees: map[string]*github.Tree{"main": tree},
		blobs: map[string][]byte{
			shaMain:   []byte("package main\n"),
			shaEnv:    []byte("SECRET=placeholder\n"),
			shaDocs:   []byte("# Intro\n"),
			shaSecret: []byte("secret\n"),
		},
	}
	srv := New(Config{
		Owner:      "owner",
		Repo:       "repo",
		Branch:     "main",
		RepoInfo:   &github.RepoInfo{FullName: "owner/repo", DefaultBranch: "main", Private: true},
		Branches:   []string{"main"},
		GitHub:     fake,
		Sessions:   session.NewManager(time.Hour, done),
		Tree:       tree,
		PathFilter: policy,
	})
	return srv, fake
}

func apiRequest(srv *Server, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("X-Relay-Token", srv.token)
	rr := httptest.NewRecorder()
	srv.srv.Handler.ServeHTTP(rr, req)
	return rr
}

func decodeTree(t *testing.T, rr *httptest.ResponseRecorder) *github.Tree {
	t.Helper()
	var tree github.Tree
	if err := json.NewDecoder(rr.Body).Decode(&tree); err != nil {
		t.Fatalf("decoding tree response: %v", err)
	}
	return &tree
}

func assertPathPresent(t *testing.T, tree *github.Tree, repoPath string) {
	t.Helper()
	if !treeContainsPath(tree, repoPath) {
		t.Fatalf("expected path %q in tree; got %#v", repoPath, tree.Tree)
	}
}

func assertPathAbsent(t *testing.T, tree *github.Tree, repoPath string) {
	t.Helper()
	if treeContainsPath(tree, repoPath) {
		t.Fatalf("expected path %q to be absent; got %#v", repoPath, tree.Tree)
	}
}

func treeContainsPath(tree *github.Tree, repoPath string) bool {
	for _, entry := range tree.Tree {
		if entry.Path == repoPath {
			return true
		}
	}
	return false
}

func mustFilter(t *testing.T, allow, deny string) *filter.Policy {
	t.Helper()
	policy, err := filter.NewPolicy(allow, deny)
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	return policy
}

func testTree() *github.Tree {
	return &github.Tree{Tree: []github.TreeEntry{
		{Path: "src", Type: "tree"},
		{Path: "src/main.go", Type: "blob", SHA: shaMain},
		{Path: "docs", Type: "tree"},
		{Path: "docs/intro.md", Type: "blob", SHA: shaDocs},
		{Path: ".env", Type: "blob", SHA: shaEnv},
		{Path: "secrets", Type: "tree"},
		{Path: "secrets/prod.yml", Type: "blob", SHA: shaSecret},
	}}
}

type fakeGitHub struct {
	trees        map[string]*github.Tree
	blobs        map[string][]byte
	getBlobCalls int
	commits      []github.CommitInfo
}

func (f *fakeGitHub) GetTree(_ context.Context, _, _, ref string) (*github.Tree, error) {
	tree, ok := f.trees[ref]
	if !ok {
		return nil, fmt.Errorf("missing tree for ref %q", ref)
	}
	return tree, nil
}

func (f *fakeGitHub) GetBlob(_ context.Context, _, _, sha string) ([]byte, error) {
	f.getBlobCalls++
	data, ok := f.blobs[sha]
	if !ok {
		return nil, fmt.Errorf("missing blob %q", sha)
	}
	return data, nil
}

func (f *fakeGitHub) GetCommits(_ context.Context, _, _, _ string) ([]github.CommitInfo, error) {
	return f.commits, nil
}

func (f *fakeGitHub) GetZipball(_ context.Context, _, _, _ string) (*http.Response, error) {
	return nil, nil
}

func TestHandleInfo(t *testing.T) {
	tree := testTree()
	srv, _ := newTestServer(t, nil, tree)

	rr := apiRequest(srv, "/api/info")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/info status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var info struct {
		Owner   string   `json:"owner"`
		Repo    string   `json:"repo"`
		Branch  string   `json:"branch"`
		Branches []string `json:"branches"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&info); err != nil {
		t.Fatalf("decoding info response: %v", err)
	}
	if info.Owner != "owner" {
		t.Fatalf("expected owner 'owner', got %q", info.Owner)
	}
	if info.Repo != "repo" {
		t.Fatalf("expected repo 'repo', got %q", info.Repo)
	}
	if info.Branch != "main" {
		t.Fatalf("expected branch 'main', got %q", info.Branch)
	}
}

func TestHandleCommits(t *testing.T) {
	tree := testTree()
	srv, fake := newTestServer(t, nil, tree)
	fake.commits = []github.CommitInfo{
		{SHA: "abc123", Commit: struct {
			Message string `json:"message"`
			Author  struct {
				Name string `json:"name"`
				Date string `json:"date"`
			} `json:"author"`
		}{Message: "feat: initial commit"}},
	}

	rr := apiRequest(srv, "/api/commits?branch=main")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/commits status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var commits []github.CommitInfo
	if err := json.NewDecoder(rr.Body).Decode(&commits); err != nil {
		t.Fatalf("decoding commits response: %v", err)
	}
	if len(commits) != 1 {
		t.Fatalf("expected 1 commit, got %d", len(commits))
	}
	if commits[0].SHA != "abc123" {
		t.Fatalf("expected commit SHA 'abc123', got %q", commits[0].SHA)
	}
}

func TestHandleBlob_Success(t *testing.T) {
	tree := testTree()
	srv, _ := newTestServer(t, nil, tree)

	rr := apiRequest(srv, fmt.Sprintf("/api/blob?branch=main&sha=%s&path=src/main.go", shaMain))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/blob status = %d, want %d: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/") {
		t.Fatalf("expected text/ content type, got %s", ct)
	}
}

func TestHandleBlob_InvalidSHA(t *testing.T) {
	tree := testTree()
	srv, _ := newTestServer(t, nil, tree)

	rr := apiRequest(srv, "/api/blob?branch=main&sha=invalid&path=src/main.go")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("GET /api/blob status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleBlob_MissingSHA(t *testing.T) {
	tree := testTree()
	srv, _ := newTestServer(t, nil, tree)

	rr := apiRequest(srv, "/api/blob?branch=main&path=src/main.go")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("GET /api/blob status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestRequireToken_InvalidToken(t *testing.T) {
	tree := testTree()
	srv, _ := newTestServer(t, nil, tree)

	req := httptest.NewRequest(http.MethodGet, "/api/tree?branch=main", nil)
	req.Header.Set("X-Relay-Token", "wrong-token")
	rr := httptest.NewRecorder()
	srv.srv.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid token, got %d", rr.Code)
	}
}

func TestRequireToken_MissingToken(t *testing.T) {
	tree := testTree()
	srv, _ := newTestServer(t, nil, tree)

	req := httptest.NewRequest(http.MethodGet, "/api/tree?branch=main", nil)
	rr := httptest.NewRecorder()
	srv.srv.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing token, got %d", rr.Code)
	}
}

func TestIsSafeSHA(t *testing.T) {
	tests := []struct {
		name     string
		sha      string
		expected bool
	}{
		{"valid 40 char hex", "abc123def7890123456789012345678901234567", true},
		{"too short", "abc123", false},
		{"invalid chars", "gh-relay-is-cool", false},
		{"uppercase hex", "ABC123DEF7890123456789012345678901234567", true},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSafeSHA(tt.sha)
			if result != tt.expected {
				t.Errorf("isSafeSHA(%q) = %v, want %v", tt.sha, result, tt.expected)
			}
		})
	}
}

func TestIsSafeBranchName(t *testing.T) {
	tests := []struct {
		name     string
		branch   string
		expected bool
	}{
		{"valid simple", "main", true},
		{"valid feature", "feature/new-auth", true},
		{"valid with numbers", "feature/auth-2fa", true},
		{"valid release tag", "v1.2.3", true},
		{"valid double dots", "feature..auth", true},
		{"valid tilde", "feature~auth", true},
		{"invalid caret", "feature^auth", false},
		{"invalid colon", "feature:auth", false},
		{"invalid question", "feature?auth", false},
		{"invalid bracket", "feature[auth", false},
		{"invalid space", "feature auth", false},
		{"invalid backslash", "feature\\auth", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSafeBranchName(tt.branch)
			if result != tt.expected {
				t.Errorf("isSafeBranchName(%q) = %v, want %v", tt.branch, result, tt.expected)
			}
		})
	}
}

func TestBlobContentType(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		check    func(t *testing.T, result string)
	}{
		{"go file", "main.go", textMimeCheck},
		{"js file", "app.js", textMimeCheck},
		{"ts file", "app.ts", textOrVideoMimeCheck},
		{"json file", "config.json", jsonMimeCheck},
		{"yaml file", "config.yaml", textMimeCheck},
		{"md file", "README.md", textMimeCheck},
		{"html file", "index.html", textMimeCheck},
		{"css file", "style.css", textMimeCheck},
		{"png file", "image.png", imageMimeCheck},
		{"unknown ext", "file.xyz", fallbackMimeCheck},
		{"no ext", "Makefile", textMimeCheck},
		{"zip file", "archive.zip", binaryMimeCheck},
		{"pdf file", "doc.pdf", binaryMimeCheck},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := blobContentType(tt.path)
			tt.check(t, result)
		})
	}
}

func textMimeCheck(t *testing.T, result string) {
	if !strings.HasPrefix(result, "text/") && result != "application/json" {
		t.Errorf("expected text MIME type, got %q", result)
	}
}

func jsonMimeCheck(t *testing.T, result string) {
	if !strings.HasPrefix(result, "application/json") {
		t.Errorf("expected application/json MIME type, got %q", result)
	}
}

func imageMimeCheck(t *testing.T, result string) {
	if !strings.HasPrefix(result, "image/") {
		t.Errorf("expected image MIME type, got %q", result)
	}
}

func binaryMimeCheck(t *testing.T, result string) {
	if !strings.HasPrefix(result, "application/") {
		t.Errorf("expected application MIME type, got %q", result)
	}
}

func textOrVideoMimeCheck(t *testing.T, result string) {
	if !strings.HasPrefix(result, "text/") && !strings.HasPrefix(result, "video/") {
		t.Errorf("expected text/ or video/ MIME type, got %q", result)
	}
}

func fallbackMimeCheck(t *testing.T, result string) {
	if result == "" {
		t.Error("expected non-empty MIME type")
	}
}

func TestAuditLog_AddAndSummary(t *testing.T) {
	al := &AuditLog{}

	al.add(AuditRecord{
		timestamp: time.Now(),
		endpoint:  "/api/blob",
		filePath:  "src/main.go",
		branch:    "main",
		ipAddress: "192.168.1.1",
	})
	al.add(AuditRecord{
		timestamp: time.Now().Add(time.Second),
		endpoint:  "/api/tree",
		branch:    "main",
		ipAddress: "192.168.1.1",
	})
	al.add(AuditRecord{
		timestamp: time.Now().Add(2 * time.Second),
		endpoint:  "/api/blob",
		filePath:  "src/main.go",
		branch:    "main",
		ipAddress: "192.168.1.1",
	})

	var buf strings.Builder
	logger := log.New(&buf, "", 0)
	al.Summary(logger)

	output := buf.String()
	if !strings.Contains(output, "Files viewed") {
		t.Error("expected audit summary to contain 'Files viewed'")
	}
	if !strings.Contains(output, "Total requests") {
		t.Error("expected audit summary to contain 'Total requests'")
	}
}

func TestAuditLog_EmptySummary(t *testing.T) {
	al := &AuditLog{}

	var buf strings.Builder
	logger := log.New(&buf, "", 0)
	al.Summary(logger)

	output := buf.String()
	if !strings.Contains(output, "No guest activity") {
		t.Error("expected empty audit summary to contain 'No guest activity'")
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name     string
		input    time.Duration
		expected string
	}{
		{"seconds", 45 * time.Second, "45s"},
		{"minutes", 2 * time.Minute, "2m0s"},
		{"hours", 1 * time.Hour, "1h0m0s"},
		{"complex", 1*time.Hour + 30*time.Minute + 15*time.Second, "1h30m15s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatDuration(tt.input)
			if result != tt.expected {
				t.Errorf("formatDuration(%v) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
