package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

// AdminOrganization is the organization owning the API key.
type AdminOrganization struct {
	ID                         string    `json:"id"`
	Name                       string    `json:"name"`
	Kind                       string    `json:"kind"`
	MaxMembers                 int       `json:"max_members"`
	CurrentPlanID              *string   `json:"current_plan_id"`
	DataroomEventRetentionDays int       `json:"dataroom_event_retention_days"`
	CreatedAt                  time.Time `json:"created_at"`
}

// AdminQuota is the member quota of the organization.
type AdminQuota struct {
	CurrentPlanID    *string `json:"current_plan_id"`
	CurrentUserCount int     `json:"current_user_count"`
	MaxUserCount     int     `json:"max_user_count"`
	IsOverQuota      bool    `json:"is_over_quota"`
	OwnerEmail       string  `json:"owner_email"`
}

// AdminMember is an organization member row.
type AdminMember struct {
	ID               string    `json:"id"`
	Email            string    `json:"email"`
	FullName         string    `json:"full_name"`
	OrganizationRole string    `json:"organization_role"`
	Status           string    `json:"status"`
	CreatedAt        time.Time `json:"created_at"`
}

// AdminUserIdentity is the Keycloak identity attached to a member, when connected.
type AdminUserIdentity struct {
	ID             string `json:"id"`
	EmailVerified  bool   `json:"email_verified"`
	TOTP           bool   `json:"totp"`
	MembershipType string `json:"membership_type"`
}

// AdminMemberDetail is a member with their Keycloak identity.
type AdminMemberDetail struct {
	AdminMember
	Identity *AdminUserIdentity `json:"identity"`
}

// AdminDomain is a blacklisted email domain.
type AdminDomain struct {
	ID         string    `json:"id"`
	DomainName string    `json:"domain_name"`
	CreatedAt  time.Time `json:"created_at"`
}

// AdminOrgPatch is a partial organization update; nil fields are not sent.
type AdminOrgPatch struct {
	Name                       *string `json:"name,omitempty"`
	APIKeyIPRestrictionEnabled *bool   `json:"api_key_ip_restriction_enabled,omitempty"`
	DataroomEventRetentionDays *int    `json:"dataroom_event_retention_days,omitempty"`
}

// AdminGetOrganization returns the organization owning the API key.
func (c *Client) AdminGetOrganization(ctx context.Context) (*AdminOrganization, error) {
	var org AdminOrganization
	if err := c.Get(ctx, "/organization", &org); err != nil {
		return nil, err
	}

	return &org, nil
}

// AdminGetQuota returns the member quota of the organization.
func (c *Client) AdminGetQuota(ctx context.Context) (*AdminQuota, error) {
	var q AdminQuota
	if err := c.Get(ctx, "/organization/quota", &q); err != nil {
		return nil, err
	}

	return &q, nil
}

// AdminGetScopes returns the scopes granted to the API key used for the request.
func (c *Client) AdminGetScopes(ctx context.Context) ([]string, error) {
	var scopes []string
	if err := c.Get(ctx, "/info/scopes", &scopes); err != nil {
		return nil, err
	}

	return scopes, nil
}

// AdminPatchOrganization partially updates the organization; nil fields are untouched.
func (c *Client) AdminPatchOrganization(ctx context.Context, patch AdminOrgPatch) (*AdminOrganization, error) {
	data, err := json.Marshal(patch)
	if err != nil {
		return nil, err
	}
	var org AdminOrganization
	if err := c.Patch(ctx, "/organization", bytes.NewReader(data), &org); err != nil {
		return nil, err
	}

	return &org, nil
}

// AdminListMembers returns one page of organization members.
func (c *Client) AdminListMembers(
	ctx context.Context, search string, includeServiceAccounts bool, page int,
) (*AdminPage[AdminMember], error) {
	q := url.Values{}
	q.Set("page", fmt.Sprint(page))
	q.Set("size", "100")
	q.Set("exclude_service_accounts", fmt.Sprint(!includeServiceAccounts))
	if search != "" {
		q.Set("search", search)
	}
	var p AdminPage[AdminMember]
	if err := c.Get(ctx, "/organization/members?"+q.Encode(), &p); err != nil {
		return nil, err
	}

	return &p, nil
}

// AdminGetMember returns a member with their Keycloak identity.
func (c *Client) AdminGetMember(ctx context.Context, userID string) (*AdminMemberDetail, error) {
	var m AdminMemberDetail
	if err := c.Get(ctx, "/organization/member/"+userID, &m); err != nil {
		return nil, err
	}

	return &m, nil
}

// AdminSetMemberRole updates the organization role of a member.
func (c *Client) AdminSetMemberRole(ctx context.Context, userID, role string) error {
	data, err := json.Marshal(map[string]string{"role": role})
	if err != nil {
		return err
	}

	return c.Put(ctx, "/organization/member/"+userID, bytes.NewReader(data), nil)
}

// AdminEnableMember re-enables a disabled member.
func (c *Client) AdminEnableMember(ctx context.Context, userID string) error {
	return c.Put(ctx, "/organization/member/"+userID+"/enable", nil, nil)
}

// AdminDisableMember disables a member.
func (c *Client) AdminDisableMember(ctx context.Context, userID string) error {
	return c.Put(ctx, "/organization/member/"+userID+"/disable", nil, nil)
}

// AdminRemoveMember removes a member from the organization. When the member's
// membership type is MANAGED, the backend also deletes their account.
func (c *Client) AdminRemoveMember(ctx context.Context, userID string) error {
	return c.Delete(ctx, "/organization/member/"+userID)
}

// AdminListBlacklistDomains returns one page of blacklisted email domains.
func (c *Client) AdminListBlacklistDomains(ctx context.Context, page int) (*AdminPage[AdminDomain], error) {
	var p AdminPage[AdminDomain]
	if err := c.Get(ctx, fmt.Sprintf("/organization/blacklist-domains?page=%d&size=100", page), &p); err != nil {
		return nil, err
	}

	return &p, nil
}

// AdminAddBlacklistDomain adds an email domain to the organization blacklist.
func (c *Client) AdminAddBlacklistDomain(ctx context.Context, domain string) (*AdminDomain, error) {
	data, err := json.Marshal(map[string]string{"domain_name": domain})
	if err != nil {
		return nil, err
	}
	var d AdminDomain
	if err := c.Post(ctx, "/organization/blacklist-domains", bytes.NewReader(data), &d); err != nil {
		return nil, err
	}

	return &d, nil
}

// AdminRemoveBlacklistDomain removes a domain from the blacklist by its ID.
func (c *Client) AdminRemoveBlacklistDomain(ctx context.Context, domainID string) error {
	return c.Delete(ctx, "/organization/blacklist-domains/"+domainID)
}
