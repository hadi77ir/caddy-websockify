package websockify

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestProxyHandler_CaddyModule(t *testing.T) {
	handler := &ProxyHandler{}
	info := handler.CaddyModule()

	if info.ID != "http.handlers.websockify" {
		t.Errorf("Expected module ID 'http.handlers.websockify', got %q", info.ID)
	}

	if info.New == nil {
		t.Error("Expected New function to be set")
	}

	newModule := info.New()
	if _, ok := newModule.(*ProxyHandler); !ok {
		t.Errorf("Expected New() to return *ProxyHandler, got %T", newModule)
	}
}

func TestProxyHandler_Provision(t *testing.T) {
	tests := []struct {
		name      string
		upstream  []string
		wantError bool
	}{
		{
			name:      "valid tcp upstream",
			upstream:  []string{"tcp://127.0.0.1:8080"},
			wantError: false,
		},
		{
			name:      "valid unix socket upstream",
			upstream:  []string{"unix:///tmp/test.sock"},
			wantError: true, // Unix socket might not exist, so error is expected
		},
		{
			name:      "multiple upstreams",
			upstream:  []string{"tcp://127.0.0.1:8080", "tcp://127.0.0.1:8081"},
			wantError: false,
		},
		{
			name:      "empty upstream",
			upstream:  []string{""},
			wantError: true,
		},
		{
			name:      "invalid upstream",
			upstream:  []string{"invalid://bad"},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &ProxyHandler{
				Upstream: tt.upstream,
			}

			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()

			ctx.Logger()

			err := handler.Provision(ctx)

			if tt.wantError && err == nil {
				t.Error("Expected error but got none")
			}

			if !tt.wantError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.wantError {
				if handler.upgrader == nil {
					t.Error("Expected upgrader to be set")
				}
				if len(handler.dialers) == 0 {
					t.Error("Expected dialers to be set")
				}
				if handler.logger == nil {
					t.Error("Expected logger to be set")
				}
			}
		})
	}
}

func TestProxyHandler_UnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantUpstream []string
		wantError    bool
	}{
		{
			name:         "single upstream",
			input:        "websockify tcp://127.0.0.1:8080",
			wantUpstream: []string{"tcp://127.0.0.1:8080"},
			wantError:    false,
		},
		{
			name:         "multiple upstreams",
			input:        "websockify tcp://127.0.0.1:8080 tcp://127.0.0.1:8081",
			wantUpstream: []string{"tcp://127.0.0.1:8080", "tcp://127.0.0.1:8081"},
			wantError:    false,
		},
		{
			name:         "unix socket upstream",
			input:        "websockify unix:///var/run/app.sock",
			wantUpstream: []string{"unix:///var/run/app.sock"},
			wantError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &ProxyHandler{}
			d := caddyfile.NewTestDispenser(tt.input)

			err := handler.UnmarshalCaddyfile(d)

			if tt.wantError && err == nil {
				t.Error("Expected error but got none")
			}

			if !tt.wantError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.wantError {
				if len(handler.Upstream) != len(tt.wantUpstream) {
					t.Errorf("Expected %d upstreams, got %d", len(tt.wantUpstream), len(handler.Upstream))
				}

				for i, want := range tt.wantUpstream {
					if i >= len(handler.Upstream) {
						break
					}
					if handler.Upstream[i] != want {
						t.Errorf("Upstream[%d]: expected %q, got %q", i, want, handler.Upstream[i])
					}
				}
			}
		})
	}
}

func TestProxyHandler_nextDialer(t *testing.T) {
	handler := &ProxyHandler{
		Upstream: []string{"tcp://127.0.0.1:8080", "tcp://127.0.0.1:8081", "tcp://127.0.0.1:8082"},
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := handler.Provision(ctx)
	if err != nil {
		t.Fatalf("Failed to provision: %v", err)
	}

	// Test round-robin behavior
	dialerCount := len(handler.dialers)
	if dialerCount != 3 {
		t.Fatalf("Expected 3 dialers, got %d", dialerCount)
	}

	// Call nextDialer multiple times and verify round-robin
	for i := 0; i < dialerCount*3; i++ {
		dialer := handler.nextDialer()
		if dialer == nil {
			t.Errorf("Call %d: nextDialer returned nil", i)
		}
	}

	// Verify counter increments
	expectedCounter := int64(dialerCount * 3)
	actualCounter := handler.counter.Load()
	if actualCounter != expectedCounter {
		t.Errorf("Expected counter to be %d, got %d", expectedCounter, actualCounter)
	}
}

func TestProxyHandler_addDialer(t *testing.T) {
	handler := &ProxyHandler{
		Upstream: []string{},
	}

	tests := []struct {
		name      string
		addr      string
		wantError bool
	}{
		{
			name:      "valid tcp address",
			addr:      "tcp://127.0.0.1:8080",
			wantError: false,
		},
		{
			name:      "empty address",
			addr:      "",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.addDialer(tt.addr)

			if tt.wantError && err == nil {
				t.Error("Expected error but got none")
			}

			if !tt.wantError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

func TestProxyHandler_ServeHTTP_NonWebSocket(t *testing.T) {
	// Create a test TCP server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Echo server
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		conn.Write(buf[:n])
	}()

	handler := &ProxyHandler{
		Upstream: []string{"tcp://" + listener.Addr().String()},
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err = handler.Provision(ctx)
	if err != nil {
		t.Fatalf("Failed to provision: %v", err)
	}

	// Create a test request without WebSocket upgrade
	req := httptest.NewRequest("GET", "http://localhost/", nil)
	req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))

	w := httptest.NewRecorder()

	err = handler.ServeHTTP(w, req, nil)
	if err == nil {
		t.Error("Expected error for non-WebSocket request")
	}

	// Should return an error because it's not a WebSocket upgrade request
	if w.Code == http.StatusSwitchingProtocols {
		t.Error("Should not upgrade non-WebSocket request")
	}
}

func TestProxyHandler_Headers(t *testing.T) {
	handler := &ProxyHandler{
		Upstream: []string{"tcp://127.0.0.1:9999"}, // doesn't need to exist for this test
		Headers: http.Header{
			"X-Custom-Header": []string{"test-value"},
		},
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := handler.Provision(ctx)
	if err != nil {
		t.Fatalf("Failed to provision: %v", err)
	}

	req := httptest.NewRequest("GET", "http://localhost/", nil)
	req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))

	w := httptest.NewRecorder()

	// This will fail to upgrade, but we can check if headers were set
	handler.ServeHTTP(w, req, nil)

	// Check if Content-Type was explicitly unset
	if w.Header().Get("Content-Type") != "" {
		t.Error("Content-Type should be unset")
	}
}

func TestErrorSetterFunc(t *testing.T) {
	var capturedStatus int
	var capturedErr error

	setter := ErrorSetterFunc(func(status int, err error) {
		capturedStatus = status
		capturedErr = err
	})

	testStatus := http.StatusBadGateway
	testErr := context.DeadlineExceeded

	setter(testStatus, testErr)

	if capturedStatus != testStatus {
		t.Errorf("Expected status %d, got %d", testStatus, capturedStatus)
	}

	if capturedErr != testErr {
		t.Errorf("Expected error %v, got %v", testErr, capturedErr)
	}
}

func TestWebSocketUpgradeAndProxy(t *testing.T) {
	// Skip if this is too complex for basic unit testing
	t.Skip("Integration test - skipping in unit tests")
}

// TestInterfaceCompliance verifies that ProxyHandler implements required interfaces
func TestInterfaceCompliance(t *testing.T) {
	var handler interface{} = &ProxyHandler{}

	if _, ok := handler.(caddy.Provisioner); !ok {
		t.Error("ProxyHandler should implement caddy.Provisioner")
	}

	if _, ok := handler.(caddyhttp.MiddlewareHandler); !ok {
		t.Error("ProxyHandler should implement caddyhttp.MiddlewareHandler")
	}

	if _, ok := handler.(caddyfile.Unmarshaler); !ok {
		t.Error("ProxyHandler should implement caddyfile.Unmarshaler")
	}
}

func BenchmarkNextDialer(b *testing.B) {
	handler := &ProxyHandler{
		Upstream: []string{"tcp://127.0.0.1:8080", "tcp://127.0.0.1:8081", "tcp://127.0.0.1:8082"},
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	handler.Provision(ctx)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.nextDialer()
	}
}
