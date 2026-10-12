// Package api provides an HTTP client for communicating with the RETYC REST API.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	// unsafeWrite is sent as unsafe_write on every chunk upload.
	unsafeWrite bool
	// missingChunkRetries are the pauses before each new attempt at a chunk
	// download answering 404 (see getChunk).
	missingChunkRetries []time.Duration
}

// Option customizes a Client at construction.
type Option func(*clientOptions)

type clientOptions struct {
	wrapTransport       func(http.RoundTripper) http.RoundTripper
	unsafeWrite         bool
	missingChunkRetries []time.Duration
}

// defaultMissingChunkRetries cover the window, about 450 ms, in which a chunk
// stored in the background is counted but not yet in the object store.
var defaultMissingChunkRetries = []time.Duration{300 * time.Millisecond, 600 * time.Millisecond}

// WithUnsafeWrite sets the unsafe_write parameter of every chunk upload. When
// true, the server answers before the chunk reaches the object store and stores
// it in the background, where a failure cannot be reported: the version stays
// incomplete although the upload succeeded. The parameter is always sent, false
// by default: the server's own default is true.
func WithUnsafeWrite(unsafe bool) Option {
	return func(o *clientOptions) { o.unsafeWrite = unsafe }
}

// WithMissingChunkRetries replaces the pauses before each new attempt at a
// chunk download answering 404; none disables the retries. For tests.
func WithMissingChunkRetries(delays ...time.Duration) Option {
	return func(o *clientOptions) { o.missingChunkRetries = delays }
}

// WrapTransport wraps the outermost RoundTripper of the client, so wrap sees
// every request exactly as sent (token and User-Agent attached). Used to plug
// metrics without touching the request path.
func WrapTransport(wrap func(http.RoundTripper) http.RoundTripper) Option {
	return func(o *clientOptions) { o.wrapTransport = wrap }
}

// New creates a Client that attaches a valid OAuth2 token to every request.
// tokSource is called before each request; it must refresh the token when expired.
// userAgent is sent as the User-Agent header on all requests.
// When insecure is true, TLS certificate verification is skipped, which allows
// connecting to servers using self-signed certificates.
// When debug is true, raw API responses are printed to stderr.
func New(baseURL, userAgent string, tokSource oauth2.TokenSource, insecure, debug bool, opts ...Option) *Client {
	o := clientOptions{missingChunkRetries: defaultMissingChunkRetries}
	for _, opt := range opts {
		opt(&o)
	}

	// BaseTransport carries the proxy settings from the environment and the
	// root CAs loaded by InitTLSRoots; only the timeouts are specific here.
	base := BaseTransport(insecure)
	base.TLSHandshakeTimeout = 15 * time.Second
	// ResponseHeaderTimeout guards against a server that accepts the
	// connection but never sends headers back. It does NOT limit how
	// long the request body (i.e. a large upload) may take to send,
	// so large chunks are not artificially timed out.
	base.ResponseHeaderTimeout = 60 * time.Second
	// IdleConnTimeout closes connections that are idle for too long,
	// protecting against a server that stops sending the response body
	// mid-transfer (e.g. stalled downloads).
	base.IdleConnTimeout = 90 * time.Second

	var transport http.RoundTripper = &UserAgentTransport{
		UserAgent: userAgent,
		Base: &oauth2.Transport{
			Source: tokSource,
			Base:   base,
		},
	}
	if o.wrapTransport != nil {
		transport = o.wrapTransport(transport)
	}

	return &Client{
		baseURL:             baseURL,
		debug:               debug,
		unsafeWrite:         o.unsafeWrite,
		missingChunkRetries: o.missingChunkRetries,
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

// getIfNoneMatch is Get for a resource the API tags with an ETag: etag, when
// not empty, is sent as If-None-Match, and the ETag of the answer is returned
// ("" when the API sends none). A 304 answers ErrNotModified, dst untouched.
func (c *Client) getIfNoneMatch(ctx context.Context, path, etag string, dst any) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	header, err := c.doHeader(req, dst)
	if err != nil {
		return "", err
	}

	return header.Get("ETag"), nil
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
	return c.postMultipart(ctx, path, nil, data, nil)
}

// formField is one text field of a multipart request.
type formField struct {
	name, value string
}

// postMultipart sends fields, then data as the upload_file part when it is
// non-nil, as multipart/form-data, and decodes the response into dst (nil
// discards it).
func (c *Client) postMultipart(ctx context.Context, path string, fields []formField, data []byte, dst any) error {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, f := range fields {
		if err := mw.WriteField(f.name, f.value); err != nil {
			return fmt.Errorf("writing multipart field %s: %w", f.name, err)
		}
	}
	if data != nil {
		part, err := mw.CreateFormFile("upload_file", "chunk.age")
		if err != nil {
			return fmt.Errorf("creating multipart field: %w", err)
		}
		if _, err := part.Write(data); err != nil {
			return fmt.Errorf("writing chunk data: %w", err)
		}
	}
	if err := mw.Close(); err != nil {
		return fmt.Errorf("closing multipart writer: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if dst != nil {
		req.Header.Set("Accept", "application/json")
	}

	return c.do(req, dst)
}

// Patch performs an authenticated PATCH request with a JSON body and decodes the response.
func (c *Client) Patch(ctx context.Context, path string, body io.Reader, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.baseURL+path, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	return c.do(req, dst)
}

// Delete performs an authenticated DELETE request.
func (c *Client) Delete(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+path, nil)
	if err != nil {
		return err
	}

	return c.do(req, nil)
}

// getChunk downloads an encrypted chunk. A chunk uploaded with unsafe_write is
// counted before it reaches the object store, so a version announced complete
// can answer 404 for it a moment: a 404 is retried after each pause of
// missingChunkRetries. A chunk still missing then is reported as
// ErrChunkMissing (which also matches ErrNotFound): the version is incomplete
// for good, e.g. its background store failed or its worker was killed. A 410
// (node pending deletion) or any other error is not retried.
func (c *Client) getChunk(ctx context.Context, path string) ([]byte, error) {
	data, err := c.GetBytes(ctx, path)
	missing := func() bool { return errors.Is(err, ErrNotFound) && !errors.Is(err, ErrGone) }
	for _, delay := range c.missingChunkRetries {
		if !missing() {
			break
		}
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		data, err = c.GetBytes(ctx, path)
	}
	if missing() {
		return nil, fmt.Errorf("%w: %w", ErrChunkMissing, err)
	}

	return data, err
}

// GetBytes performs an authenticated GET and returns the raw response body.
func (c *Client) GetBytes(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}

	if c.debug {
		fmt.Fprintf(os.Stderr, "> GET %s%s\n", req.URL, ProxyLabel(req))
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
		return nil, statusError(resp.StatusCode, body)
	}

	return body, nil
}

// do executes the request and decodes the response body into dst (if non-nil).
// It returns an error for non-2xx status codes.
func (c *Client) do(req *http.Request, dst any) error {
	_, err := c.doHeader(req, dst)

	return err
}

// doHeader is do, also returning the headers of a 2xx response.
func (c *Client) doHeader(req *http.Request, dst any) (http.Header, error) {
	if c.debug {
		fmt.Fprintf(os.Stderr, "> %s %s%s\n", req.Method, req.URL, ProxyLabel(req))
	}

	resp, err := c.httpClient.Do(req) //nolint:gosec // G704: intentional outbound HTTP request from API client
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
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
		return nil, statusError(resp.StatusCode, body)
	}

	if dst != nil {
		if err := json.Unmarshal(body, dst); err != nil {
			return nil, fmt.Errorf("decoding response: %w", err)
		}
	}

	return resp.Header, nil
}

// HTTPError is the error of a non-2xx response. It matches the sentinels of
// its status through errors.Is (ErrConflict for 409, ErrNotFound for 404 and
// 410, ErrGone for 410, ErrLocked for 423, ErrNotModified for 304) and exposes
// the status and body for callers that need to tell apart two refusals with
// the same status (see Detail).
type HTTPError struct {
	Status int
	Body   string
}

// Error keeps the historical messages: "conflict: <body>" for a 409,
// "API error <code>: <body>" otherwise.
func (e *HTTPError) Error() string {
	switch e.Status {
	case http.StatusConflict:
		return fmt.Sprintf("%s: %s", ErrConflict, e.Body)
	case http.StatusNotFound:
		return fmt.Sprintf("API error %d: %s: %s", e.Status, e.Body, ErrNotFound)
	case http.StatusGone:
		return fmt.Sprintf("API error %d: %s: %s: %s", e.Status, e.Body, ErrGone, ErrNotFound)
	default:
		return fmt.Sprintf("API error %d: %s", e.Status, e.Body)
	}
}

// Is reports the sentinel(s) of the status, so errors.Is keeps working on an
// HTTPError exactly as it did on the wrapped sentinels.
func (e *HTTPError) Is(target error) bool {
	switch target {
	case ErrConflict:
		return e.Status == http.StatusConflict
	case ErrNotFound:
		return e.Status == http.StatusNotFound || e.Status == http.StatusGone
	case ErrGone:
		return e.Status == http.StatusGone
	case ErrLocked:
		return e.Status == http.StatusLocked
	case ErrNotModified:
		return e.Status == http.StatusNotModified
	default:
		return false
	}
}

// Detail returns the "detail" string of a JSON error body ({"detail": "..."}),
// the form the API uses for its stable refusal codes (mime_type_unknown,
// mime_types_limit, ...), or "" when the body has no such string.
func (e *HTTPError) Detail() string {
	var payload struct {
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal([]byte(e.Body), &payload); err != nil {
		return ""
	}

	return payload.Detail
}

// ErrorDetail returns the detail code of the HTTPError in err's chain, or ""
// when err is not an API refusal or carries no string detail.
func ErrorDetail(err error) string {
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.Detail()
	}

	return ""
}

// statusError builds the error of a non-2xx response.
func statusError(code int, body []byte) error {
	return &HTTPError{Status: code, Body: string(body)}
}
