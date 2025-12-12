package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/inkog-io/inkog/pkg/contract"
)

func TestSendScan_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/scan" {
			t.Errorf("expected /api/v1/scan, got %s", r.URL.Path)
		}

		response := contract.ScanResponse{
			Success: true,
			ScanResult: contract.ScanResult{
				FindingsCount: 3,
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewInkogClient(server.URL, true, nil)
	result, err := client.SendScan("multipart/form-data", bytes.NewBuffer([]byte("test")))

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ScanResult.FindingsCount != 3 {
		t.Errorf("expected 3 findings, got %d", result.ScanResult.FindingsCount)
	}
}

func TestSendScan_RetryOn429(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{
				"code":    "RATE_LIMIT",
				"message": "Too many requests",
			})
			return
		}
		response := contract.ScanResponse{Success: true}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewInkogClient(server.URL, true, nil)
	client.BaseBackoff = 10 * time.Millisecond // Speed up test
	_, err := client.SendScan("multipart/form-data", bytes.NewBuffer([]byte("test")))

	if err != nil {
		t.Fatalf("expected success after retries, got error: %v", err)
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestSendScan_RetryOn5xx(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{
				"code":    "WORKER_TIMEOUT",
				"message": "Service unavailable",
			})
			return
		}
		response := contract.ScanResponse{Success: true}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewInkogClient(server.URL, true, nil)
	client.BaseBackoff = 10 * time.Millisecond // Speed up test
	_, err := client.SendScan("multipart/form-data", bytes.NewBuffer([]byte("test")))

	if err != nil {
		t.Fatalf("expected success after retries, got error: %v", err)
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestSendScan_NoRetryOn4xx(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"code":    "BAD_REQUEST",
			"message": "Invalid request",
		})
	}))
	defer server.Close()

	client := NewInkogClient(server.URL, true, nil)
	_, err := client.SendScan("multipart/form-data", bytes.NewBuffer([]byte("test")))

	if err == nil {
		t.Fatal("expected error for 400 response")
	}
	if attempts != 1 {
		t.Errorf("expected 1 attempt (no retry for 4xx), got %d", attempts)
	}
}

func TestCalculateBackoff(t *testing.T) {
	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{1, 2 * time.Second},
		{2, 4 * time.Second},
		{3, 8 * time.Second},
		{4, 16 * time.Second},
		{10, 30 * time.Second}, // Capped at max
	}

	client := NewInkogClient("http://test", true, nil)
	for _, tt := range tests {
		t.Run(fmt.Sprintf("attempt_%d", tt.attempt), func(t *testing.T) {
			got := client.calculateBackoff(tt.attempt)
			if got != tt.expected {
				t.Errorf("calculateBackoff(%d) = %v, want %v", tt.attempt, got, tt.expected)
			}
		})
	}
}

func TestStatusCodeToErrorCode(t *testing.T) {
	tests := []struct {
		statusCode int
		expected   string
	}{
		{400, "BAD_REQUEST"},
		{401, "UNAUTHORIZED"},
		{403, "FORBIDDEN"},
		{404, "NOT_FOUND"},
		{409, "CONFLICT"},
		{429, "RATE_LIMIT"},
		{500, "SERVER_ERROR"},
		{502, "BAD_GATEWAY"},
		{503, "WORKER_TIMEOUT"},
		{504, "GATEWAY_TIMEOUT"},
		{418, "HTTP_418"}, // Teapot - unknown code
	}

	client := NewInkogClient("http://test", true, nil)
	for _, tt := range tests {
		t.Run(fmt.Sprintf("status_%d", tt.statusCode), func(t *testing.T) {
			got := client.statusCodeToErrorCode(tt.statusCode)
			if got != tt.expected {
				t.Errorf("statusCodeToErrorCode(%d) = %s, want %s", tt.statusCode, got, tt.expected)
			}
		})
	}
}

func TestHumanizeErrorCode(t *testing.T) {
	tests := []struct {
		code     string
		expected string
	}{
		{"WORKER_TIMEOUT", "Analysis timed out"},
		{"RATE_LIMIT", "Too many requests"},
		{"UNAUTHORIZED", "Authentication required"},
		{"FORBIDDEN", "Access denied"},
		{"BAD_REQUEST", "Invalid request"},
		{"SERVER_ERROR", "Internal server error"},
		{"BAD_GATEWAY", "Server temporarily unavailable"},
		{"GATEWAY_TIMEOUT", "Server response timed out"},
		{"SCAN_FAILED", "Scan analysis failed"},
		{"UNKNOWN_CODE", "An error occurred"},
	}

	client := NewInkogClient("http://test", true, nil)
	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			got := client.humanizeErrorCode(tt.code)
			if got != tt.expected {
				t.Errorf("humanizeErrorCode(%s) = %s, want %s", tt.code, got, tt.expected)
			}
		})
	}
}

func TestGetRetryAfter(t *testing.T) {
	client := NewInkogClient("http://test", true, nil)

	// Test with server error retry_after
	t.Run("from_server_error", func(t *testing.T) {
		serverErr := &ServerError{RetryAfter: 60}
		resp := &http.Response{Header: make(http.Header)}
		got := client.getRetryAfter(resp, serverErr)
		if got != 60 {
			t.Errorf("expected 60, got %d", got)
		}
	})

	// Test with Retry-After header
	t.Run("from_header", func(t *testing.T) {
		serverErr := &ServerError{}
		resp := &http.Response{Header: make(http.Header)}
		resp.Header.Set("Retry-After", "45")
		got := client.getRetryAfter(resp, serverErr)
		if got != 45 {
			t.Errorf("expected 45, got %d", got)
		}
	})

	// Test default
	t.Run("default", func(t *testing.T) {
		serverErr := &ServerError{}
		resp := &http.Response{Header: make(http.Header)}
		got := client.getRetryAfter(resp, serverErr)
		if got != 30 {
			t.Errorf("expected default 30, got %d", got)
		}
	})
}

func TestServerError_Error(t *testing.T) {
	err := &ServerError{
		Code:      "WORKER_TIMEOUT",
		Message:   "Analysis timed out",
		RequestID: "req_123",
	}

	got := err.Error()
	expected := "WORKER_TIMEOUT: Analysis timed out (request_id: req_123)"
	if got != expected {
		t.Errorf("Error() = %s, want %s", got, expected)
	}
}

func TestNewInkogClient_Defaults(t *testing.T) {
	client := NewInkogClient("http://test.com", false, nil)

	if client.BaseURL != "http://test.com" {
		t.Errorf("expected BaseURL http://test.com, got %s", client.BaseURL)
	}
	if client.MaxRetries != 3 {
		t.Errorf("expected MaxRetries 3, got %d", client.MaxRetries)
	}
	if client.BaseBackoff != 2*time.Second {
		t.Errorf("expected BaseBackoff 2s, got %v", client.BaseBackoff)
	}
	if client.Quiet != false {
		t.Error("expected Quiet false")
	}
	if client.HTTPClient.Timeout != 60*time.Second {
		t.Errorf("expected HTTPClient.Timeout 60s, got %v", client.HTTPClient.Timeout)
	}
}
