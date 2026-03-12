// Package api provides an HTTP client for communicating with the RETYC REST API.
package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"time"

	"golang.org/x/oauth2"
)

// UserAgentTransport is an http.RoundTripper that injects a User-Agent header into every request.
type UserAgentTransport struct {
	UserAgent string
	Base      http.RoundTripper
}

// RoundTrip clones the request, sets the User-Agent header, and delegates to the wrapped transport.
// Falls back to http.DefaultTransport when Base is nil.
func (t *UserAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("User-Agent", t.UserAgent)
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}

	return base.RoundTrip(req)
}

// Client is an authenticated HTTP client for the RETYC API.
type Client struct {
	baseURL    string
	httpClient *http.Client
	debug      bool
}

// New creates a Client that attaches a valid OAuth2 token to every request.
// tokSource is called before each request; it must refresh the token when expired.
// userAgent is sent as the User-Agent header on all requests.
// When insecure is true, TLS certificate verification is skipped, which allows
// connecting to servers using self-signed certificates.
// When debug is true, raw API responses are printed to stderr.
func New(baseURL, userAgent string, tokSource oauth2.TokenSource, insecure, debug bool) *Client {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: insecure, // #nosec G402 — intentional, controlled by --insecure flag
	}
	transport := &UserAgentTransport{
		UserAgent: userAgent,
		Base: &oauth2.Transport{
			Source: tokSource,
			Base: &http.Transport{
				TLSClientConfig:     tlsCfg,
				TLSHandshakeTimeout: 15 * time.Second,
				// ResponseHeaderTimeout guards against a server that accepts the
				// connection but never sends headers back. It does NOT limit how
				// long the request body (i.e. a large upload) may take to send,
				// so large chunks are not artificially timed out.
				ResponseHeaderTimeout: 60 * time.Second,
				// IdleConnTimeout closes connections that are idle for too long,
				// protecting against a server that stops sending the response body
				// mid-transfer (e.g. stalled downloads).
				IdleConnTimeout: 90 * time.Second,
			},
		},
	}

	return &Client{
		baseURL: baseURL,
		debug:   debug,
		// No client-level Timeout: that field caps the entire round-trip
		// (including body upload), which would kill large chunk uploads on
		// slow connections. Transport-level timeouts above protect against
		// hung connections and unresponsive servers instead.
		httpClient: &http.Client{
			Transport: transport,
		},
	}
}

// Get performs an authenticated GET request and decodes the JSON response into dst.
func (c *Client) Get(ctx context.Context, path string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	return c.do(req, dst)
}

// Post performs an authenticated POST request with a JSON body and decodes the response.
func (c *Client) Post(ctx context.Context, path string, body io.Reader, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	return c.do(req, dst)
}

// Put performs an authenticated PUT request with a JSON body and decodes the response.
func (c *Client) Put(ctx context.Context, path string, body io.Reader, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+path, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	return c.do(req, dst)
}

// PostMultipartChunk uploads binary data as multipart/form-data with field "upload_file".
func (c *Client) PostMultipartChunk(ctx context.Context, path string, data []byte) error {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, err := mw.CreateFormFile("upload_file", "chunk.age")
	if err != nil {
		return fmt.Errorf("creating multipart field: %w", err)
	}
	if _, err := part.Write(data); err != nil {
		return fmt.Errorf("writing chunk data: %w", err)
	}
	if err := mw.Close(); err != nil {
		return fmt.Errorf("closing multipart writer: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())

	return c.do(req, nil)
}

// Delete performs an authenticated DELETE request.
func (c *Client) Delete(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+path, nil)
	if err != nil {
		return err
	}

	return c.do(req, nil)
}

// GetBytes performs an authenticated GET and returns the raw response body.
func (c *Client) GetBytes(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}

	if c.debug {
		fmt.Fprintf(os.Stderr, "> GET %s\n", req.URL)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if c.debug {
		fmt.Fprintf(os.Stderr, "< %s (%d bytes, binary)\n", resp.Status, len(body))
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// do executes the request and decodes the response body into dst (if non-nil).
// It returns an error for non-2xx status codes.
func (c *Client) do(req *http.Request, dst any) error {
	if c.debug {
		fmt.Fprintf(os.Stderr, "> %s %s\n", req.Method, req.URL)
	}

	resp, err := c.httpClient.Do(req) //nolint:gosec // G704: intentional outbound HTTP request from API client
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	if c.debug {
		fmt.Fprintf(os.Stderr, "< %s\n", resp.Status)
		if len(body) > 0 {
			var buf bytes.Buffer
			if json.Indent(&buf, body, "  ", "  ") == nil {
				fmt.Fprintf(os.Stderr, "  %s\n", buf.String())
			} else {
				fmt.Fprintf(os.Stderr, "  %s\n", body)
			}
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	if dst != nil {
		if err := json.Unmarshal(body, dst); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}

	return nil
}
