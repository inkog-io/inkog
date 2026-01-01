package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/inkog-io/inkog/pkg/contract"
)

// ServerError represents a structured error response from the backend
type ServerError struct {
	Code       string `json:"code"`                  // WORKER_TIMEOUT, RATE_LIMIT, etc.
	RequestID  string `json:"request_id"`            // req_123
	Message    string `json:"message"`               // Human-readable message
	RetryAfter int    `json:"retry_after,omitempty"` // Seconds to wait (for 429)
}

// Error implements the error interface
func (e *ServerError) Error() string {
	return fmt.Sprintf("%s: %s (request_id: %s)", e.Code, e.Message, e.RequestID)
}

// InkogClient wraps HTTP communication with retry logic and error handling
type InkogClient struct {
	BaseURL     string
	APIKey      string // API key for authentication (from INKOG_API_KEY env var)
	HTTPClient  *http.Client
	MaxRetries  int
	BaseBackoff time.Duration
	Quiet       bool // Suppress retry messages
	progress    *ProgressReporter
}

// NewInkogClient creates a new client with sensible defaults.
// Reads API key from INKOG_API_KEY environment variable.
func NewInkogClient(baseURL string, quiet bool, progress *ProgressReporter) *InkogClient {
	return &InkogClient{
		BaseURL: baseURL,
		APIKey:  os.Getenv("INKOG_API_KEY"), // Read API key from environment
		HTTPClient: &http.Client{
			Timeout: 60 * time.Second, // 60s timeout for large uploads
		},
		MaxRetries:  3,
		BaseBackoff: 2 * time.Second,
		Quiet:       quiet,
		progress:    progress,
	}
}

// SendScan sends a multipart scan request to the server with retry logic
func (c *InkogClient) SendScan(contentType string, body *bytes.Buffer) (*contract.ScanResponse, error) {
	var lastErr error

	for attempt := 1; attempt <= c.MaxRetries; attempt++ {
		// Create a new buffer for each attempt (body gets consumed)
		bodyBytes := body.Bytes()
		reqBody := bytes.NewBuffer(bodyBytes)

		req, err := http.NewRequest("POST", c.BaseURL+"/api/v1/scan", reqBody)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("User-Agent", "inkog-cli/"+CLIVersion)

		// Set API key authentication if available
		if c.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+c.APIKey)
		}

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("network error: %w", err)
			if attempt < c.MaxRetries {
				c.logRetry(attempt, "Network error, retrying...")
				time.Sleep(c.calculateBackoff(attempt))
				continue
			}
			return nil, lastErr
		}
		defer resp.Body.Close()

		// Handle response based on status code
		switch {
		case resp.StatusCode == http.StatusOK:
			// Success - parse response
			return c.parseSuccessResponse(resp.Body)

		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusConflict:
			// Rate limited (429 or 409)
			serverErr := c.parseErrorResponse(resp)
			retryAfter := c.getRetryAfter(resp, serverErr)

			if attempt < c.MaxRetries {
				c.logRateLimit(attempt, retryAfter)
				time.Sleep(time.Duration(retryAfter) * time.Second)
				continue
			}
			return nil, fmt.Errorf("rate limit exceeded after %d attempts", c.MaxRetries)

		case resp.StatusCode >= 500:
			// Server error - retry
			serverErr := c.parseErrorResponse(resp)
			lastErr = serverErr

			if attempt < c.MaxRetries {
				c.logRetry(attempt, fmt.Sprintf("Server error (%d), retrying...", resp.StatusCode))
				time.Sleep(c.calculateBackoff(attempt))
				continue
			}
			return nil, c.formatUserError(serverErr)

		default:
			// Client error (4xx) - don't retry
			serverErr := c.parseErrorResponse(resp)
			return nil, c.formatUserError(serverErr)
		}
	}

	return nil, lastErr
}

// parseSuccessResponse parses a successful scan response
func (c *InkogClient) parseSuccessResponse(body io.Reader) (*contract.ScanResponse, error) {
	var scanResponse contract.ScanResponse
	if err := json.NewDecoder(body).Decode(&scanResponse); err != nil {
		return nil, fmt.Errorf("failed to parse server response: %w", err)
	}

	if !scanResponse.Success {
		return nil, &ServerError{
			Code:    "SCAN_FAILED",
			Message: scanResponse.Error,
		}
	}

	return &scanResponse, nil
}

// parseErrorResponse extracts structured error from response
func (c *InkogClient) parseErrorResponse(resp *http.Response) *ServerError {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &ServerError{
			Code:    c.statusCodeToErrorCode(resp.StatusCode),
			Message: fmt.Sprintf("HTTP %d", resp.StatusCode),
		}
	}

	// Try to parse as structured JSON error
	var serverErr ServerError
	if err := json.Unmarshal(body, &serverErr); err != nil {
		// Fallback to generic error
		return &ServerError{
			Code:    c.statusCodeToErrorCode(resp.StatusCode),
			Message: string(body),
		}
	}

	// Fill in defaults if missing
	if serverErr.Code == "" {
		serverErr.Code = c.statusCodeToErrorCode(resp.StatusCode)
	}
	if serverErr.Message == "" {
		serverErr.Message = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}

	return &serverErr
}

// statusCodeToErrorCode maps HTTP status to error codes
func (c *InkogClient) statusCodeToErrorCode(statusCode int) string {
	switch statusCode {
	case 400:
		return "BAD_REQUEST"
	case 401:
		return "UNAUTHORIZED"
	case 403:
		return "FORBIDDEN"
	case 404:
		return "NOT_FOUND"
	case 409:
		return "CONFLICT"
	case 429:
		return "RATE_LIMIT"
	case 500:
		return "SERVER_ERROR"
	case 502:
		return "BAD_GATEWAY"
	case 503:
		return "WORKER_TIMEOUT"
	case 504:
		return "GATEWAY_TIMEOUT"
	default:
		return fmt.Sprintf("HTTP_%d", statusCode)
	}
}

// getRetryAfter extracts retry delay from response
func (c *InkogClient) getRetryAfter(resp *http.Response, serverErr *ServerError) int {
	// Check server error first
	if serverErr.RetryAfter > 0 {
		return serverErr.RetryAfter
	}

	// Check Retry-After header
	if header := resp.Header.Get("Retry-After"); header != "" {
		if seconds, err := strconv.Atoi(header); err == nil {
			return seconds
		}
	}

	// Default to 30 seconds
	return 30
}

// calculateBackoff returns exponential backoff duration
func (c *InkogClient) calculateBackoff(attempt int) time.Duration {
	// Exponential backoff: 2s, 4s, 8s...
	backoff := c.BaseBackoff * time.Duration(1<<uint(attempt-1))
	if backoff > 30*time.Second {
		backoff = 30 * time.Second
	}
	return backoff
}

// formatUserError creates a user-friendly error message
func (c *InkogClient) formatUserError(serverErr *ServerError) error {
	msg := fmt.Sprintf("Server Error: %s (Code: %s)", c.humanizeErrorCode(serverErr.Code), serverErr.Code)
	if serverErr.RequestID != "" {
		msg += fmt.Sprintf("\n   Request ID: %s (Please quote this in support)", serverErr.RequestID)
	}
	return fmt.Errorf(msg)
}

// humanizeErrorCode converts error codes to human-readable messages
func (c *InkogClient) humanizeErrorCode(code string) string {
	switch code {
	case "WORKER_TIMEOUT":
		return "Analysis timed out"
	case "RATE_LIMIT":
		return "Too many requests"
	case "UNAUTHORIZED":
		return "Authentication required"
	case "FORBIDDEN":
		return "Access denied"
	case "BAD_REQUEST":
		return "Invalid request"
	case "SERVER_ERROR":
		return "Internal server error"
	case "BAD_GATEWAY":
		return "Server temporarily unavailable"
	case "GATEWAY_TIMEOUT":
		return "Server response timed out"
	case "SCAN_FAILED":
		return "Scan analysis failed"
	default:
		return "An error occurred"
	}
}

// logRetry logs retry attempts (respects quiet mode)
func (c *InkogClient) logRetry(attempt int, message string) {
	if c.Quiet {
		return
	}
	if c.progress != nil {
		c.progress.Update(fmt.Sprintf("%s (Attempt %d/%d)", message, attempt+1, c.MaxRetries))
	} else {
		fmt.Fprintf(os.Stderr, "   %s (Attempt %d/%d)\n", message, attempt+1, c.MaxRetries)
	}
}

// logRateLimit logs rate limit wait (respects quiet mode)
func (c *InkogClient) logRateLimit(attempt int, seconds int) {
	if c.Quiet {
		return
	}
	msg := fmt.Sprintf("Rate limited. Retrying in %ds... (Attempt %d/%d)", seconds, attempt+1, c.MaxRetries)
	if c.progress != nil {
		c.progress.Update(msg)
	} else {
		fmt.Fprintf(os.Stderr, "   %s\n", msg)
	}
}
