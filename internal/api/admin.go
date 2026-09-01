package api

import "context"

// AdminPage is the generic paginated envelope returned by the admin API listings.
type AdminPage[T any] struct {
	Items []T `json:"items"`
	Total int `json:"total"`
	Page  int `json:"page"`
	Pages int `json:"pages"`
}

// GetAllAdminPages walks a paginated admin listing until the last page and
// returns the concatenated items. pathFn receives the 1-based page number and
// must return the full request path including its query string.
func GetAllAdminPages[T any](ctx context.Context, c *Client, pathFn func(page int) string) ([]T, error) {
	var all []T
	for page := 1; ; page++ {
		var p AdminPage[T]
		if err := c.Get(ctx, pathFn(page), &p); err != nil {
			return nil, err
		}
		all = append(all, p.Items...)
		if page >= p.Pages {
			return all, nil
		}
	}
}
