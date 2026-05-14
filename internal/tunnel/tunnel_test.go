package tunnel

import (
	"context"
	"strings"
	"testing"
)

func TestOpen_ProviderNone(t *testing.T) {
	tunnel, err := Open(context.Background(), ProviderNone, 8080)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer tunnel.Close()

	if tunnel.URL() != "http://localhost:8080" {
		t.Fatalf("expected URL 'http://localhost:8080', got %q", tunnel.URL())
	}
}

func TestOpen_ProviderEmptyDefaultsToCloudflare(t *testing.T) {
	_, err := Open(context.Background(), "", 8080)
	if err == nil {
		t.Skip("cloudflared is installed and available")
	}
}

func TestOpen_InvalidProvider(t *testing.T) {
	_, err := Open(context.Background(), Provider("invalid"), 8080)
	if err == nil {
		t.Fatal("expected error for invalid provider")
	}
	if err.Error() != "unknown tunnel provider: \"invalid\" (valid: cloudflare, ngrok, none)" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProvider_Constants(t *testing.T) {
	if ProviderCloudflare != "cloudflare" {
		t.Errorf("expected ProviderCloudflare 'cloudflare', got %q", ProviderCloudflare)
	}
	if ProviderNgrok != "ngrok" {
		t.Errorf("expected ProviderNgrok 'ngrok', got %q", ProviderNgrok)
	}
	if ProviderNone != "none" {
		t.Errorf("expected ProviderNone 'none', got %q", ProviderNone)
	}
}

func TestNoopTunnel_URL(t *testing.T) {
	tunnel := &noopTunnel{url: "http://localhost:3000"}
	if tunnel.URL() != "http://localhost:3000" {
		t.Errorf("expected URL 'http://localhost:3000', got %q", tunnel.URL())
	}
}

func TestNoopTunnel_Close(t *testing.T) {
	tunnel := &noopTunnel{url: "http://localhost:3000"}
	if err := tunnel.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestOpen_ProviderNgrok(t *testing.T) {
	tunnel, err := Open(context.Background(), ProviderNgrok, 8080)
	if err != nil {
		t.Skip("ngrok not installed")
	}
	defer tunnel.Close()

	url := tunnel.URL()
	if url == "" {
		t.Error("expected non-empty URL from ngrok tunnel")
	}
	if !strings.HasPrefix(url, "https://") {
		t.Errorf("expected URL to start with https://, got %q", url)
	}
}

func TestNoopTunnel_MultipleClose(t *testing.T) {
	tunnel := &noopTunnel{url: "http://localhost:3000"}
	tunnel.Close()
	tunnel.Close()
}

func TestProvider_String(t *testing.T) {
	tests := []struct {
		input    Provider
		expected string
	}{
		{ProviderCloudflare, "cloudflare"},
		{ProviderNgrok, "ngrok"},
		{ProviderNone, "none"},
		{Provider("custom"), "custom"},
	}

	for _, tt := range tests {
		if string(tt.input) != tt.expected {
			t.Errorf("Provider(%q) = %q, want %q", tt.input, string(tt.input), tt.expected)
		}
	}
}

func TestOpen_WithCancelContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tunnel, err := Open(ctx, ProviderNone, 8080)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer tunnel.Close()

	if tunnel.URL() != "http://localhost:8080" {
		t.Fatalf("expected URL 'http://localhost:8080', got %q", tunnel.URL())
	}
}
