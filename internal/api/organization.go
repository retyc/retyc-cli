// Package api — organization routes of the user API.
package api

import (
	"context"
	"errors"
	"time"
)

// ServiceAccountStatusActive is the status of a service account whose key
// may be added to new datarooms.
const ServiceAccountStatusActive = "active"

// ServiceAccount is the organization's service account, the holder of the
// organization key (GET /organization/service-account). The organization key
// is an ordinary age recipient: datarooms and transfers include it by
// encrypting their session key for PublicKey.
type ServiceAccount struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	FullName  *string   `json:"full_name"`
	PublicKey *string   `json:"public_key"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// OrganizationKey returns the public key to add to a new dataroom, or "" when
// there is none to add: no service account, a disabled one (still returned by
// the API, but nothing new must be encrypted for it) or one without a key.
func (sa *ServiceAccount) OrganizationKey() string {
	if sa == nil || sa.Status != ServiceAccountStatusActive || sa.PublicKey == nil {
		return ""
	}

	return *sa.PublicKey
}

// GetOrganizationServiceAccount returns the service account of the caller's
// organization, nil when the organization has none (or lost the organization
// key feature). An API that predates the route answers 404, read as none too.
func (c *Client) GetOrganizationServiceAccount(ctx context.Context) (*ServiceAccount, error) {
	var result *ServiceAccount
	if err := c.Get(ctx, "/organization/service-account", &result); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, nil
		}

		return nil, err
	}

	return result, nil
}
