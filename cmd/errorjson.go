package cmd

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/auth"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/vfs"
)

// errorJSON is what printError writes on stderr with --json. Error and Kind
// are always present; Status and Detail only when the error carries an API
// refusal (an *api.HTTPError in its chain), Code only when that refusal
// carries an X-Error-Code.
//
// Kind is the stable field a script branches on (see errorKind), and Code the
// API's own stable code, verbatim: Detail is the API's wording, which may
// change and may hold numbers.
type errorJSON struct {
	Error  string `json:"error"`
	Kind   string `json:"kind"`
	Status int    `json:"status,omitempty"`
	Code   string `json:"code,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// The kinds of errorJSON. A new kind is added at need; an existing one is
// never renamed nor given another meaning (doc/commands.md lists them).
const (
	kindAuthRequired     = "auth_required"
	kindConfig           = "config"
	kindLostWrites       = "lost_writes"
	kindNeedsYes         = "needs_yes"
	kindRateLimited      = "rate_limited"
	kindStorageExceeded  = "storage_exceeded"
	kindPlanExceeded     = "plan_exceeded"
	kindCapacityTooSmall = "capacity_too_small"
	kindCapacityShrink   = "capacity_shrink"
	kindUnauthenticated  = "unauthenticated"
	kindForbidden        = "forbidden"
	kindNotFound         = "not_found"
	kindGone             = "gone"
	kindConflict         = "conflict"
	kindLocked           = "locked"
	kindInvalid          = "invalid"
	kindCLITooOld        = "cli_too_old"
	kindAPIError         = "api_error"
	kindError            = "error"
)

// The former detail texts of the storage refusals, read only when the
// refusal carries no code (an API that predates X-Error-Code).
const (
	capacityTooSmallMsg   = "Reserved storage capacity must be at least"
	capacityShrinkDetail  = "A reservation can only be enlarged"
	planExceededDetailPre = "Not enough storage left on"
)

// newErrorJSON builds the JSON view of err.
func newErrorJSON(err error) errorJSON {
	v := errorJSON{Error: err.Error(), Kind: errorKind(err)}
	var httpErr *api.HTTPError
	if errors.As(err, &httpErr) {
		v.Status = httpErr.Status
		v.Code = httpErr.Code
		v.Detail = httpDetail(httpErr)
	}

	return v
}

// errorKind classifies err, first match wins. The order follows exitCode:
// a lost login (77) or a configuration error (78) is told before the writes
// lost with it (75), and a rate limit before the 429 it wraps.
func errorKind(err error) string {
	var httpErr *api.HTTPError
	status, code, detail := 0, "", ""
	if errors.As(err, &httpErr) {
		status, code, detail = httpErr.Status, httpErr.Code, httpDetail(httpErr)
	}
	// The detail texts below are the fallback of a refusal without a code.
	legacy := code == ""
	var lost lostWritesError
	switch {
	case errors.Is(err, auth.ErrNoToken), errors.Is(err, auth.ErrNoRefreshToken):
		return kindAuthRequired
	case errors.Is(err, config.ErrNoKeyPassphrase), errors.Is(err, service.ErrWrongKeyPassphrase),
		errors.Is(err, config.ErrEnvFile):
		return kindConfig
	case errors.As(err, &lost):
		return kindLostWrites
	case errors.Is(err, errJSONNeedsYes):
		return kindNeedsYes
	case errors.Is(err, api.ErrRateLimited):
		return kindRateLimited
	case errors.Is(err, vfs.ErrStorageExceeded), api.IsStorageExceeded(err):
		return kindStorageExceeded
	case code == api.CodeStoragePlanExceeded,
		legacy && status == http.StatusBadRequest && strings.HasPrefix(detail, planExceededDetailPre):
		return kindPlanExceeded
	case code == api.CodeStorageCapacityTooSmall,
		legacy && status == http.StatusUnprocessableEntity && strings.Contains(detail, capacityTooSmallMsg):
		return kindCapacityTooSmall
	case code == api.CodeStorageCapacityShrink,
		legacy && status == http.StatusBadRequest && detail == capacityShrinkDetail:
		return kindCapacityShrink
	case status == http.StatusUnauthorized, errors.Is(err, vfs.ErrUnauthenticated):
		return kindUnauthenticated
	case status == http.StatusForbidden, errors.Is(err, vfs.ErrForbidden):
		return kindForbidden
	case status == http.StatusNotFound:
		return kindNotFound
	case status == http.StatusGone:
		return kindGone
	case status == http.StatusConflict:
		return kindConflict
	case status == http.StatusLocked:
		return kindLocked
	case status == http.StatusUpgradeRequired:
		return kindCLITooOld
	case status == http.StatusBadRequest, status == http.StatusUnprocessableEntity:
		return kindInvalid
	case status != 0:
		return kindAPIError
	}

	return kindError
}

// httpDetail returns the detail of an API refusal: the "detail" string of
// its JSON body, or for a validation error (422, a list of
// {"loc", "msg", "type"}) the messages joined by "; ". "" when the body has
// neither.
func httpDetail(e *api.HTTPError) string {
	if d := e.Detail(); d != "" {
		return d
	}
	var payload struct {
		Detail []struct {
			Msg string `json:"msg"`
		} `json:"detail"`
	}
	if json.Unmarshal([]byte(e.Body), &payload) != nil {
		return ""
	}
	msgs := make([]string, 0, len(payload.Detail))
	for _, d := range payload.Detail {
		if d.Msg != "" {
			msgs = append(msgs, d.Msg)
		}
	}

	return strings.Join(msgs, "; ")
}
