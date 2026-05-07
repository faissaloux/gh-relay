package cmd

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"testing"
	"time"

	"github.ibm.com/soub4i/gh-relay/internal/filter"
	"github.ibm.com/soub4i/gh-relay/internal/github"
)

const (
	testSHAEnv    = "1111111111111111111111111111111111111111"
	testSHAPem    = "2222222222222222222222222222222222222222"
	testSHASecret = "3333333333333333333333333333333333333333"
)

func TestSecretPreflightIgnoresDeniedPaths(t *testing.T) {
	tree := &github.Tree{Tree: []github.TreeEntry{
		{Path: ".env", Type: "blob", SHA: testSHAEnv, Size: 16},
		{Path: "deploy/prod.pem", Type: "blob", SHA: testSHAPem, Size: 16},
		{Path: "secrets", Type: "tree"},
		{Path: "secrets/prod.yml", Type: "blob", SHA: testSHASecret, Size: 16},
	}}
	fake := &secretPreflightFakeGitHub{tree: tree}
	policy := mustSharePolicy(t, "", ".env,*.pem,secrets/**")

	_, err := runSecretPreflight(
		context.Background(),
		log.New(io.Discard, "", 0),
		fake,
		"owner",
		"repo",
		"main",
		shareFlags{scanSecrets: true, scanContent: true, failOnSecrets: true},
		policy,
	)
	if err != nil {
		t.Fatalf("runSecretPreflight() error = %v", err)
	}
	if fake.getBlobCalls != 0 {
		t.Fatalf("GetBlob calls = %d, want 0 for denied content paths", fake.getBlobCalls)
	}
}

func mustSharePolicy(t *testing.T, allow, deny string) *filter.Policy {
	t.Helper()
	policy, err := filter.NewPolicy(allow, deny)
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	return policy
}

type secretPreflightFakeGitHub struct {
	tree         *github.Tree
	getBlobCalls int
}

func (f *secretPreflightFakeGitHub) GetTree(_ context.Context, _, _, _ string) (*github.Tree, error) {
	return f.tree, nil
}

func (f *secretPreflightFakeGitHub) GetBlob(_ context.Context, _, _, sha string) ([]byte, error) {
	f.getBlobCalls++
	return nil, fmt.Errorf("denied blob %s should not be fetched", sha)
}

func TestValidateShareFlags_Valid(t *testing.T) {
	f := shareFlags{
		token:  "ghp_testtoken123",
		repo:   "owner/repo",
		port:   8080,
		branch: "main",
	}
	err := ValidateShareFlags(f)
	if err != nil {
		t.Fatalf("ValidateShareFlags() error = %v", err)
	}
}

func TestValidateShareFlags_MissingToken(t *testing.T) {
	f := shareFlags{
		token: "",
		repo:  "owner/repo",
	}
	err := ValidateShareFlags(f)
	if err == nil {
		t.Fatal("expected error for missing token")
	}
}

func TestValidateShareFlags_MissingRepo(t *testing.T) {
	f := shareFlags{
		token: "ghp_testtoken",
		repo:  "",
	}
	err := ValidateShareFlags(f)
	if err == nil {
		t.Fatal("expected error for missing repo")
	}
}

func TestValidateShareFlags_InvalidPort_TooLow(t *testing.T) {
	f := shareFlags{
		token: "ghp_testtoken",
		repo:  "owner/repo",
		port:  0,
	}
	err := ValidateShareFlags(f)
	if err == nil {
		t.Fatal("expected error for port 0")
	}
}

func TestValidateShareFlags_InvalidPort_TooHigh(t *testing.T) {
	f := shareFlags{
		token: "ghp_testtoken",
		repo:  "owner/repo",
		port:  70000,
	}
	err := ValidateShareFlags(f)
	if err == nil {
		t.Fatal("expected error for port > 65535")
	}
}

func TestValidateShareFlags_InvalidAllowPattern(t *testing.T) {
	f := shareFlags{
		token: "ghp_testtoken",
		repo:  "owner/repo",
		allow: "../secret",
	}
	err := ValidateShareFlags(f)
	if err == nil {
		t.Fatal("expected error for invalid allow pattern")
	}
}

func TestValidateShareFlags_ValidPortBoundaries(t *testing.T) {
	tests := []struct {
		name string
		port int
	}{
		{"min valid", 1},
		{"max valid", 65535},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := shareFlags{
				token: "ghp_testtoken",
				repo:  "owner/repo",
				port:  tt.port,
			}
			err := ValidateShareFlags(f)
			if err != nil {
				t.Fatalf("ValidateShareFlags() error = %v", err)
			}
		})
	}
}

func TestVisibilityLabel(t *testing.T) {
	if visibilityLabel(true) != "private" {
		t.Error("expected 'private' for true")
	}
	if visibilityLabel(false) != "public" {
		t.Error("expected 'public' for false")
	}
}

func TestContainsString(t *testing.T) {
	ss := []string{"a", "b", "c"}
	if !containsString(ss, "a") {
		t.Error("expected 'a' to be in slice")
	}
	if !containsString(ss, "b") {
		t.Error("expected 'b' to be in slice")
	}
	if containsString(ss, "d") {
		t.Error("expected 'd' not to be in slice")
	}
	if containsString(nil, "a") {
		t.Error("expected nil slice to return false")
	}
}

func TestSecretScanEntries(t *testing.T) {
	entries := []github.TreeEntry{
		{Path: "src/main.go", Type: "blob", Size: 100},
		{Path: "docs", Type: "tree"},
	}
	result := secretScanEntries(entries)
	if len(result) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(result))
	}
	if result[0].Path != "src/main.go" {
		t.Errorf("expected path 'src/main.go', got %q", result[0].Path)
	}
	if result[0].Type != "blob" {
		t.Errorf("expected type 'blob', got %q", result[0].Type)
	}
}

func TestWaitForServer_Timeout(t *testing.T) {
	err := waitForServer("http://localhost:9999/v1/health", 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected error for server that doesn't exist")
	}
}

func TestWaitForServer_Success(t *testing.T) {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	url := "http://" + ln.Addr().String() + "/v1/health"
	err = waitForServer(url, 2*time.Second)
	if err != nil {
		t.Fatalf("waitForServer() error = %v", err)
	}
}
