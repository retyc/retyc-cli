package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetAllAdminPages_WalksAllPages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		switch page {
		case "1":
			fmt.Fprint(w, `{"items":["a","b"],"total":3,"page":1,"pages":2}`)
		case "2":
			fmt.Fprint(w, `{"items":["c"],"total":3,"page":2,"pages":2}`)
		default:
			t.Errorf("unexpected page %q", page)
		}
	}))
	defer srv.Close()

	items, err := GetAllAdminPages[string](context.Background(), newTestClient(srv), func(page int) string {
		return fmt.Sprintf("/things?page=%d&size=100", page)
	})
	if err != nil {
		t.Fatalf("GetAllAdminPages() error = %v", err)
	}
	if len(items) != 3 || items[0] != "a" || items[2] != "c" {
		t.Errorf("items = %v, want [a b c]", items)
	}
}

func TestGetAllAdminPages_EmptyFirstPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"items":[],"total":0,"page":1,"pages":0}`)
	}))
	defer srv.Close()

	items, err := GetAllAdminPages[string](context.Background(), newTestClient(srv), func(page int) string {
		return fmt.Sprintf("/things?page=%d", page)
	})
	if err != nil {
		t.Fatalf("GetAllAdminPages() error = %v", err)
	}
	if len(items) != 0 {
		t.Errorf("items = %v, want empty", items)
	}
}

func TestAdminListMembers_QueryParams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/organization/members" {
			t.Errorf("path = %s", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("search") != "bob" || q.Get("exclude_service_accounts") != "true" {
			t.Errorf("unexpected query: %s", r.URL.RawQuery)
		}
		fmt.Fprint(w, `{"items":[{"id":"u1","email":"bob@x.co","full_name":"Bob",`+
			`"organization_role":"member","status":"active"}],"total":1,"page":1,"pages":1}`)
	}))
	defer srv.Close()

	page, err := newTestClient(srv).AdminListMembers(context.Background(), "bob", false, 1)
	if err != nil {
		t.Fatalf("AdminListMembers() error = %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].Email != "bob@x.co" {
		t.Errorf("unexpected result: %+v", page)
	}
}

func TestAdminPatchOrganization_OnlySetFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/organization" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if len(body) != 1 || body["name"] != "New Name" {
			t.Errorf("body = %v, want only name", body)
		}
		fmt.Fprint(w, `{"id":"o1","name":"New Name","kind":"company","max_members":10,"current_plan_id":null}`)
	}))
	defer srv.Close()

	name := "New Name"
	org, err := newTestClient(srv).AdminPatchOrganization(context.Background(), AdminOrgPatch{Name: &name})
	if err != nil {
		t.Fatalf("AdminPatchOrganization() error = %v", err)
	}
	if org.Name != "New Name" {
		t.Errorf("Name = %q", org.Name)
	}
}

func TestAdminGetScopes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/info/scopes" {
			t.Errorf("path = %s", r.URL.Path)
		}
		fmt.Fprint(w, `["organization:read","dataroom:read"]`)
	}))
	defer srv.Close()

	scopes, err := newTestClient(srv).AdminGetScopes(context.Background())
	if err != nil {
		t.Fatalf("AdminGetScopes() error = %v", err)
	}
	if len(scopes) != 2 || scopes[0] != "organization:read" {
		t.Errorf("scopes = %v", scopes)
	}
}
