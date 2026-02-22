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
	"time"

	"golang.org/x/oauth2"
)

// Client is an authenticated HTTP client for the RETYC API.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// New creates a Client that attaches the provided OAuth2 token to every request.
// When insecure is true, TLS certificate verification is skipped, which allows
// connecting to servers using self-signed certificates.
func New(baseURL string, tok *oauth2.Token, insecure bool) *Client {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: insecure, // #nosec G402 — intentional, controlled by --insecure flag
	}
	transport := &oauth2.Transport{
		Source: oauth2.StaticTokenSource(tok),
		Base: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
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

// do executes the request and decodes the response body into dst (if non-nil).
// It returns an error for non-2xx status codes.
func (c *Client) do(req *http.Request, dst any) error {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	if dst != nil {
		if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}
	return nil
}
