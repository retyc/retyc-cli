// Package api — machine account enrollment routes (private surface,
// anonymous: the caller has no token yet).
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/retyc/retyc-cli/internal/machinekey"
)

// ErrMachineUnsupported is matched by the refusal of POST /machine/enrollments
// by an API that does not know the route (a 404 that is not
// ErrUnknownOrganization). It also matches ErrNotFound.
var ErrMachineUnsupported = errors.New("the API does not support machine accounts")

// ErrUnknownOrganization is matched by the 404 of POST /machine/enrollments
// whose detail says the organization does not exist. It also matches
// ErrNotFound.
var ErrUnknownOrganization = errors.New("unknown organization")

// unknownOrganizationDetail is the detail of the 404 for an unknown
// organization.
const unknownOrganizationDetail = "Unknown organization"

// Enrollment states returned by GET /machine/enrollments/{id}.
const (
	EnrollmentPending  = "pending"
	EnrollmentApproved = "approved"
	EnrollmentDenied   = "denied"
	EnrollmentExpired  = "expired"
)

// EnrollmentRequest is the body of POST /machine/enrollments.
type EnrollmentRequest struct {
	OrganizationID string         `json:"organization_id"`
	SigningJWK     machinekey.JWK `json:"signing_jwk"`
	AgeRecipient   string         `json:"age_recipient"`
	DisplayName    string         `json:"display_name"`
	ClusterUID     *string        `json:"cluster_uid,omitempty"`
}

// Enrollment is the answer to the creation of an enrollment.
type Enrollment struct {
	EnrollmentID string `json:"enrollment_id"`
	Fingerprint  string `json:"fingerprint"`
	ApprovalURI  string `json:"approval_uri"`
	ExpiresIn    int    `json:"expires_in"`
	Interval     int    `json:"interval"`
}

// EnrollmentStatus is the state of an enrollment. Everything but State is nil
// until the enrollment is approved.
type EnrollmentStatus struct {
	State          string  `json:"state"`
	MachineID      *string `json:"machine_id"`
	OrganizationID *string `json:"organization_id"`
	ClientID       *string `json:"client_id"`
	Issuer         *string `json:"issuer"`
	TokenEndpoint  *string `json:"token_endpoint"`
}

// sentinelError adds a sentinel to an error without replacing it: errors.Is
// and errors.As reach both, and the message is the original one.
type sentinelError struct {
	sentinel error
	err      error
}

func (e *sentinelError) Error() string   { return e.err.Error() }
func (e *sentinelError) Unwrap() []error { return []error{e.sentinel, e.err} }

// CreateEnrollment registers a pending enrollment. It sends no credentials.
// A 404 is wrapped with ErrUnknownOrganization or ErrMachineUnsupported.
func (c *Client) CreateEnrollment(ctx context.Context, req EnrollmentRequest) (*Enrollment, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	var out Enrollment
	if err := c.Post(ctx, "/machine/enrollments", bytes.NewReader(body), &out); err != nil {
		var httpErr *HTTPError
		if errors.As(err, &httpErr) && httpErr.Status == http.StatusNotFound {
			sentinel := ErrMachineUnsupported
			if httpErr.Detail() == unknownOrganizationDetail {
				sentinel = ErrUnknownOrganization
			}

			return nil, &sentinelError{sentinel: sentinel, err: err}
		}

		return nil, err
	}

	return &out, nil
}

// GetEnrollment returns the state of an enrollment. A 404 is a plain
// ErrNotFound.
func (c *Client) GetEnrollment(ctx context.Context, id string) (*EnrollmentStatus, error) {
	var out EnrollmentStatus
	if err := c.Get(ctx, "/machine/enrollments/"+url.PathEscape(id), &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// ErrMachineKeyAlreadyActive is matched by the 409 of POST /machine/me/key
// when the proposed key is already the active one.
var ErrMachineKeyAlreadyActive = errors.New("this age key is already the active one")

// ErrMachineRotationUnfinished is matched by the 409 of POST /machine/me/key
// while the datarooms of the previous rotation are not rekeyed yet.
var ErrMachineRotationUnfinished = errors.New("previous key rotation not finished")

// Details of the 409 answers of POST /machine/me/key (no X-Error-Code).
const (
	machineKeyAlreadyActiveDetail   = "This age key is already the active one"
	machineRotationUnfinishedDetail = "Previous key rotation not finished: some datarooms are not rekeyed yet"
)

// MachineKeyRotation is the answer of POST /machine/me/key.
type MachineKeyRotation struct {
	Fingerprint string `json:"fingerprint"`
}

// RotateMachineKey sends the signed rotation proof of a machine account. The
// 409 answers are matched by ErrKeyRotationInProgress,
// ErrMachineKeyAlreadyActive and ErrMachineRotationUnfinished.
func (c *Client) RotateMachineKey(ctx context.Context, proof string) (*MachineKeyRotation, error) {
	data, err := json.Marshal(map[string]string{"proof": proof})
	if err != nil {
		return nil, err
	}

	var out MachineKeyRotation
	if err := c.Post(ctx, "/machine/me/key", bytes.NewReader(data), &out); err != nil {
		return nil, conflictSentinel(err, map[string]error{
			keyRotationInProgressDetail:     ErrKeyRotationInProgress,
			machineKeyAlreadyActiveDetail:   ErrMachineKeyAlreadyActive,
			machineRotationUnfinishedDetail: ErrMachineRotationUnfinished,
		})
	}

	return &out, nil
}
