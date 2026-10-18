package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/retyc/retyc-cli/internal/machinekey"
)

func anonClient(srv *httptest.Server) *Client {
	return New(srv.URL, "retyc-test/1.0", nil, false, false)
}

func TestCreateEnrollmentBody(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/machine/enrollments" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		if _, ok := r.Header["Authorization"]; ok {
			t.Errorf("Authorization header sent: %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("User-Agent") != "retyc-test/1.0" {
			t.Errorf("User-Agent = %q", r.Header.Get("User-Agent"))
		}
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"enrollment_id":"e1","fingerprint":"ABCD-EFGH-IJKL-MNOP",` +
			`"approval_uri":"https://x/approve","expires_in":600,"interval":5}`))
	}))
	defer srv.Close()

	uid := "uid-1"
	en, err := anonClient(srv).CreateEnrollment(context.Background(), EnrollmentRequest{
		OrganizationID: "org",
		SigningJWK:     machinekey.JWK{Kty: "EC", Crv: "P-256", X: "x", Y: "y", Kid: "k", Alg: "ES256", Use: "sig"},
		AgeRecipient:   "age1pq1abc",
		DisplayName:    "box",
		ClusterUID:     &uid,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"organization_id":"org","signing_jwk":{"kty":"EC","crv":"P-256","x":"x","y":"y",` +
		`"kid":"k","alg":"ES256","use":"sig"},"age_recipient":"age1pq1abc",` +
		`"display_name":"box","cluster_uid":"uid-1"}`
	if gotBody != want {
		t.Errorf("body = %s\nwant   %s", gotBody, want)
	}
	want2 := Enrollment{"e1", "ABCD-EFGH-IJKL-MNOP", "https://x/approve", 600, 5}
	if *en != want2 {
		t.Errorf("enrollment = %+v", en)
	}
}

func TestCreateEnrollmentOmitsClusterUID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]json.RawMessage
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &m)
		if _, ok := m["cluster_uid"]; ok {
			t.Errorf("cluster_uid present: %s", b)
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	if _, err := anonClient(srv).CreateEnrollment(context.Background(), EnrollmentRequest{}); err != nil {
		t.Fatal(err)
	}
}

func TestNewNilTokenSourceSendsNoAuthorization(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Header["Authorization"]; ok {
			t.Errorf("Authorization sent")
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	if err := anonClient(srv).Get(context.Background(), "/x", &struct{}{}); err != nil {
		t.Fatal(err)
	}
}

func TestCreateEnrollment404(t *testing.T) {
	tests := []struct {
		name, body string
		want       error
		not        error
	}{
		{"unknown org", `{"detail":"Unknown organization"}`, ErrUnknownOrganization, ErrMachineUnsupported},
		{"no detail", ``, ErrMachineUnsupported, ErrUnknownOrganization},
		{"default detail", `{"detail":"Not Found"}`, ErrMachineUnsupported, ErrUnknownOrganization},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()
			_, err := anonClient(srv).CreateEnrollment(context.Background(), EnrollmentRequest{})
			if !errors.Is(err, tt.want) || errors.Is(err, tt.not) || !errors.Is(err, ErrNotFound) {
				t.Errorf("err = %v", err)
			}
			var he *HTTPError
			if !errors.As(err, &he) || he.Status != 404 {
				t.Errorf("no HTTPError in %v", err)
			}
		})
	}
}

func TestCreateEnrollmentOtherErrorUntouched(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	_, err := anonClient(srv).CreateEnrollment(context.Background(), EnrollmentRequest{})
	if err == nil || errors.Is(err, ErrMachineUnsupported) || errors.Is(err, ErrUnknownOrganization) {
		t.Errorf("err = %v", err)
	}
}

func TestGetEnrollmentApproved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.EscapedPath() != "/machine/enrollments/a%2Fb" {
			t.Errorf("got %s %s", r.Method, r.URL.EscapedPath())
		}
		_, _ = w.Write([]byte(`{"state":"approved","machine_id":"m","organization_id":"o",` +
			`"client_id":"c","issuer":"i","token_endpoint":"t"}`))
	}))
	defer srv.Close()
	st, err := anonClient(srv).GetEnrollment(context.Background(), "a/b")
	if err != nil {
		t.Fatal(err)
	}
	got := []string{st.State, *st.MachineID, *st.OrganizationID, *st.ClientID, *st.Issuer, *st.TokenEndpoint}
	if !slices.Equal(got, []string{EnrollmentApproved, "m", "o", "c", "i", "t"}) {
		t.Errorf("status = %+v", st)
	}
}

func TestGetEnrollmentPendingNulls(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"state":"pending","machine_id":null,"token_endpoint":null}`))
	}))
	defer srv.Close()
	st, err := anonClient(srv).GetEnrollment(context.Background(), "e")
	if err != nil || st.State != EnrollmentPending || st.MachineID != nil || st.TokenEndpoint != nil {
		t.Errorf("st=%+v err=%v", st, err)
	}
}

func TestGetEnrollment404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"detail":"Unknown organization"}`))
	}))
	defer srv.Close()
	_, err := anonClient(srv).GetEnrollment(context.Background(), "e")
	if !errors.Is(err, ErrNotFound) || errors.Is(err, ErrMachineUnsupported) || errors.Is(err, ErrUnknownOrganization) {
		t.Errorf("err = %v", err)
	}
}
