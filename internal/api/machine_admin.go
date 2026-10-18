// Package api — management of the machine accounts of the caller's
// organization (private surface, organization admins only).
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Machine account statuses (MachineAccount.Status).
const (
	MachineActive   = "active"
	MachineInactive = "inactive"
)

// ErrNoOrganizationKeyAck is matched by the 409 of an approval in an
// organization that has no organization key, sent without the
// acknowledgement. It also matches ErrConflict.
var ErrNoOrganizationKeyAck = errors.New("the organization has no organization key")

// MachineAccount is a machine account of the organization.
type MachineAccount struct {
	ID          string    `json:"id"`
	DisplayName string    `json:"display_name"`
	Fingerprint string    `json:"fingerprint"`
	ClusterUID  *string   `json:"cluster_uid"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   *string   `json:"created_by"`
}

// MachineEnrollment is a pending enrollment of the organization.
// ReplacesMachineID is the active machine with the same cluster UID, if any.
type MachineEnrollment struct {
	ID                string    `json:"id"`
	DisplayName       string    `json:"display_name"`
	Fingerprint       string    `json:"fingerprint"`
	ClusterUID        *string   `json:"cluster_uid"`
	CreatedIP         *string   `json:"created_ip"`
	CreatedAt         time.Time `json:"created_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	ReplacesMachineID *string   `json:"replaces_machine_id"`
}

// ListMachines returns the machine accounts of the organization.
func (c *Client) ListMachines(ctx context.Context) ([]MachineAccount, error) {
	var out []MachineAccount
	if err := c.Get(ctx, "/organization/machines", &out); err != nil {
		return nil, err
	}

	return out, nil
}

// ListMachineEnrollments returns the pending, unexpired enrollments of the
// organization.
func (c *Client) ListMachineEnrollments(ctx context.Context) ([]MachineEnrollment, error) {
	var out []MachineEnrollment
	if err := c.Get(ctx, "/organization/machines/enrollments", &out); err != nil {
		return nil, err
	}

	return out, nil
}

// ApproveMachineEnrollment approves a pending enrollment and returns the
// machine account created. noOrgKeyAck acknowledges that the organization has
// no organization key; without it, such an approval is refused with
// ErrNoOrganizationKeyAck.
func (c *Client) ApproveMachineEnrollment(
	ctx context.Context, id, displayName string, noOrgKeyAck bool,
) (*MachineAccount, error) {
	body, err := json.Marshal(map[string]any{"display_name": displayName, "no_master_key_acknowledged": noOrgKeyAck})
	if err != nil {
		return nil, err
	}
	var out MachineAccount
	path := "/organization/machines/enrollments/" + url.PathEscape(id) + "/approve"
	if err := c.Post(ctx, path, bytes.NewReader(body), &out); err != nil {
		// No error code on this route: the detail is the only way to tell
		// the missing acknowledgement from an enrollment no longer pending.
		var httpErr *HTTPError
		if errors.As(err, &httpErr) && httpErr.Status == http.StatusConflict &&
			strings.Contains(strings.ToLower(httpErr.Detail()), "no master key") {
			return nil, &sentinelError{sentinel: ErrNoOrganizationKeyAck, err: err}
		}

		return nil, err
	}

	return &out, nil
}

// DenyMachineEnrollment refuses a pending enrollment.
func (c *Client) DenyMachineEnrollment(ctx context.Context, id string) error {
	return c.Post(ctx, "/organization/machines/enrollments/"+url.PathEscape(id)+"/deny", nil, nil)
}

// SetMachineEnabled enables or disables a machine account. Both are
// idempotent.
func (c *Client) SetMachineEnabled(ctx context.Context, id string, enabled bool) error {
	action := "/disable"
	if enabled {
		action = "/enable"
	}

	return c.Put(ctx, "/organization/machines/"+url.PathEscape(id)+action, nil, nil)
}

// DeleteMachine deletes a machine account. The API refuses it (409,
// ErrConflict) while the machine owns datarooms, deleted ones not purged yet
// included.
func (c *Client) DeleteMachine(ctx context.Context, id string) error {
	return c.Delete(ctx, "/organization/machines/"+url.PathEscape(id))
}
