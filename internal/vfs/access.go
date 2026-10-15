package vfs

import (
	"context"
	"errors"

	"github.com/retyc/retyc-cli/internal/api"
)

// Access is what the user may do in a dataroom, as the API tells it.
type Access struct {
	// Role is the user's role ("viewer", "editor"...), "" when the API does
	// not tell or the dataroom is not in the user's list.
	Role string
	// Writable is false when the plan of the dataroom's owner refuses
	// writes; true when the API does not tell.
	Writable bool
	// ReadOnly is true when no write of this user can succeed: a viewer, or a
	// dataroom that is not writable. False is no promise: the API still
	// decides each write (a folder's own rules, a lock, the storage).
	ReadOnly bool
}

// Reason says why the dataroom is read-only, for a message to the operator;
// "" when it is not.
func (a Access) Reason() string {
	switch {
	case !a.ReadOnly:
		return ""
	case a.Role == api.RoleViewer:
		return "you are a viewer of this dataroom"
	default:
		return "the plan of its owner refuses writes"
	}
}

// Access reports what the user may do in the dataroom. What the API does not
// tell counts as allowed, so an older API never makes a dataroom read-only:
// an unknown role is not a viewer, a missing writable flag is writable.
//
// The role comes from the list of datarooms, as cached (see Datarooms: no
// request unless the list is missing or too old); the state of the owner's
// plan from one GET /dataroom/{id}, asked every time. Nothing is cached
// here: a front end asks once per dataroom, and again when it wants the
// answer refreshed. A dataroom the list does not name has no known role.
func (fs *FS) Access(ctx context.Context, dataroomID string) (Access, error) {
	if fs.client == nil {
		return Access{}, errors.New("no API client to read the dataroom with")
	}
	list, err := fs.Datarooms(ctx)
	if err != nil {
		return Access{}, err
	}
	var a Access
	for _, dr := range list {
		if dr.ID == dataroomID {
			a.Role = dr.Role

			break
		}
	}
	detail, err := fs.client.GetDataroom(ctx, dataroomID)
	if err != nil {
		if errors.Is(err, api.ErrNotFound) {
			return Access{}, as(ErrNotExist, err)
		}

		return Access{}, classify(err)
	}
	a.Writable = detail.CanWrite()
	a.ReadOnly = a.Role == api.RoleViewer || !a.Writable

	return a, nil
}
