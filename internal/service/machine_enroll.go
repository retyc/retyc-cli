package service

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/machinekey"
)

// Sentinels of Enroll. cmd maps ErrEnrollmentDenied to the configuration exit
// code (78); the others exit 1.
var (
	// ErrEnrollmentExpired: the request expired (or was purged) unanswered.
	ErrEnrollmentExpired = errors.New("the enrollment request expired")
	// ErrEnrollmentDenied: an administrator refused the request.
	ErrEnrollmentDenied = errors.New("the enrollment request was denied")
	// ErrFingerprintMismatch: the server's fingerprint differs from the local
	// one, so nobody must approve the request.
	ErrFingerprintMismatch = errors.New("the server's fingerprint does not match the local one")
)

// Enrollment event kinds.
const (
	EnrollPending  = "pending"
	EnrollApproved = "approved"
	EnrollDenied   = "denied"
	EnrollExpired  = "expired"
)

const (
	enrollFileVersion  = 1
	defaultPollSeconds = 5
	pollGrace          = 30 * time.Second
)

// EnrollParams are the inputs of Enroll. Now and Sleep default to the real
// clock; tests inject fakes.
type EnrollParams struct {
	OrganizationID string
	Dir            string
	DisplayName    string
	ClusterUID     *string
	Now            func() time.Time
	Sleep          func(ctx context.Context, d time.Duration) error
}

// EnrollEvent is one step of the enrollment. Kind is pending, approved,
// denied or expired; only the fields of that step are set. No json tags: the
// command renders its own view.
type EnrollEvent struct {
	Kind           string
	EnrollmentID   string
	Fingerprint    string
	ApprovalURI    string // empty when a pending request is resumed
	ExpiresAt      time.Time
	MachineID      string
	OrganizationID string
	ClientID       string
}

// Enroll runs the machine enrollment in p.Dir (see the state table in the
// design spec). emit is required and is called synchronously: pending once per
// run, then approved, denied or expired. Keys are written before any API
// call and never regenerated; client is anonymous.
func Enroll(ctx context.Context, client *api.Client, p EnrollParams, emit func(EnrollEvent)) error {
	if p.Dir == "" || p.OrganizationID == "" {
		return fmt.Errorf("%w: enrollment needs an organization and an output directory", config.ErrMachineConfig)
	}
	if p.Now == nil {
		p.Now = time.Now
	}
	if p.Sleep == nil {
		p.Sleep = sleepCtx
	}
	if err := os.MkdirAll(p.Dir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", p.Dir, err)
	}

	info, err := config.ReadMachineInfo(p.Dir)
	if err != nil {
		return err
	}
	if info != nil {
		if !strings.EqualFold(info.OrganizationID, p.OrganizationID) {
			return fmt.Errorf("%w: %s is already enrolled in another organization",
				config.ErrMachineConfig, p.Dir)
		}
		// Already enrolled: the keys must be there, and are never generated.
		if err := requireMachineKeys(p.Dir); err != nil {
			return err
		}
		emit(EnrollEvent{Kind: EnrollApproved, MachineID: info.MachineID,
			OrganizationID: info.OrganizationID, ClientID: info.ClientID})

		return nil
	}
	sigKey, ageRecipient, generated, err := loadOrCreateMachineKeys(p.Dir)
	if err != nil {
		return err
	}

	jwk := machinekey.PublicJWK(&sigKey.PublicKey)
	fingerprint := machinekey.Fingerprint(jwk.Kid, ageRecipient)
	e := &enroller{client: client, p: p, emit: emit, fingerprint: fingerprint}

	// A request left by a previous run is bound to the previous keys: when
	// the keys were generated just now it is stale and is ignored (the POST
	// below replaces it).
	if !generated {
		prev, err := config.ReadEnrollmentInfo(p.Dir)
		if err != nil {
			return err
		}
		if prev != nil && strings.EqualFold(prev.OrganizationID, p.OrganizationID) {
			done, err := e.resume(ctx, prev)
			if done || err != nil {
				return err
			}
		}
	}

	req := api.EnrollmentRequest{OrganizationID: p.OrganizationID, SigningJWK: jwk,
		AgeRecipient: ageRecipient, DisplayName: p.DisplayName, ClusterUID: p.ClusterUID}
	enr, err := client.CreateEnrollment(ctx, req)
	if err != nil {
		return wrapCreateError(err)
	}
	if enr.Fingerprint != fingerprint {
		return ErrFingerprintMismatch
	}
	expires := p.Now().Add(time.Duration(enr.ExpiresIn) * time.Second).UTC()
	if err := writeEnrollmentFile(p.Dir, enr.EnrollmentID, p.OrganizationID, expires); err != nil {
		return err
	}
	e.announce(EnrollEvent{Kind: EnrollPending, EnrollmentID: enr.EnrollmentID,
		ApprovalURI: enr.ApprovalURI, ExpiresAt: expires})

	st, err := e.wait(ctx, enr.EnrollmentID, expires, enr.Interval)
	if err != nil {
		return err
	}

	return e.finish(enr.EnrollmentID, st)
}

// enroller carries the state shared by the resume and the fresh request.
type enroller struct {
	client      *api.Client
	p           EnrollParams
	emit        func(EnrollEvent)
	fingerprint string
	announced   bool
}

// announce emits the pending event once per run.
func (e *enroller) announce(ev EnrollEvent) {
	if e.announced {
		return
	}
	e.announced = true
	ev.Fingerprint = e.fingerprint
	e.emit(ev)
}

// resume polls the request of a previous run. It returns done when the run is
// over; (false, nil) means the request was already gone at the first poll and
// a new one must be made.
func (e *enroller) resume(ctx context.Context, prev *config.EnrollmentInfo) (bool, error) {
	st, err := e.wait(ctx, prev.EnrollmentID, prev.ExpiresAt, 0)
	if err != nil {
		return true, err
	}
	// Once pending was emitted in this run the driver knows this request: its
	// expiry ends the run instead of silently making another one.
	if st.State == api.EnrollmentExpired && !e.announced {
		return false, nil
	}

	return true, e.finish(prev.EnrollmentID, st)
}

// wait polls until a decision. A pending answer announces the request (a
// no-op after the first); transient failures are retried up to the deadline
// (expiry + grace), after which the request counts as expired.
func (e *enroller) wait(
	ctx context.Context, id string, expires time.Time, interval int,
) (*api.EnrollmentStatus, error) {
	if interval <= 0 {
		interval = defaultPollSeconds
	}
	deadline := expires.Add(pollGrace)
	for {
		st, err := e.client.GetEnrollment(ctx, id)
		switch {
		case err == nil:
			if st.State != api.EnrollmentPending {
				return st, nil
			}
			e.announce(EnrollEvent{Kind: EnrollPending, EnrollmentID: id, ExpiresAt: expires})
		case ctx.Err() != nil:
			return nil, ctx.Err()
		case errors.Is(err, api.ErrNotFound):
			return &api.EnrollmentStatus{State: api.EnrollmentExpired}, nil
		case !transientPollError(err):
			return nil, err
		}
		if !e.p.Now().Before(deadline) {
			return &api.EnrollmentStatus{State: api.EnrollmentExpired}, nil
		}
		if err := e.p.Sleep(ctx, time.Duration(interval)*time.Second); err != nil {
			return nil, err
		}
	}
}

// finish turns a final status into an event, a file and a return value.
func (e *enroller) finish(id string, st *api.EnrollmentStatus) error {
	switch st.State {
	case api.EnrollmentDenied:
		e.emit(EnrollEvent{Kind: EnrollDenied, EnrollmentID: id})

		return ErrEnrollmentDenied
	case api.EnrollmentExpired:
		e.emit(EnrollEvent{Kind: EnrollExpired, EnrollmentID: id})

		return ErrEnrollmentExpired
	case api.EnrollmentApproved:
		return e.approve(st)
	}

	return fmt.Errorf("unexpected enrollment state %q", st.State)
}

// approve writes machine.json from an approved status.
func (e *enroller) approve(st *api.EnrollmentStatus) error {
	if st.ClientID == nil || st.TokenEndpoint == nil || *st.ClientID == "" || *st.TokenEndpoint == "" {
		return errors.New("malformed approval: the API sent no client_id or token_endpoint")
	}
	if st.OrganizationID != nil && !strings.EqualFold(*st.OrganizationID, e.p.OrganizationID) {
		return fmt.Errorf("%w: the approval is for another organization than %s",
			config.ErrMachineConfig, e.p.OrganizationID)
	}
	info := config.MachineInfo{Version: enrollFileVersion, ClientID: *st.ClientID,
		TokenEndpoint: *st.TokenEndpoint, OrganizationID: e.p.OrganizationID}
	if st.MachineID != nil {
		info.MachineID = *st.MachineID
	}
	if st.Issuer != nil {
		info.Issuer = *st.Issuer
	}
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}
	if err := config.WriteMachineFile(e.p.Dir, config.MachineFile, append(data, '\n')); err != nil {
		return err
	}
	e.emit(EnrollEvent{Kind: EnrollApproved, MachineID: info.MachineID,
		OrganizationID: info.OrganizationID, ClientID: info.ClientID})

	return nil
}

// transientPollError reports whether a poll failure is worth retrying: network
// errors, 5xx and 429.
func transientPollError(err error) bool {
	if errors.Is(err, api.ErrRateLimited) {
		return true
	}
	var httpErr *api.HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.Status >= http.StatusInternalServerError
	}

	return true
}

// wrapCreateError gives the refusals of the creation a clear message and the
// configuration sentinel, keeping the original error reachable.
func wrapCreateError(err error) error {
	var httpErr *api.HTTPError
	switch {
	case errors.Is(err, api.ErrUnknownOrganization):
		return fmt.Errorf("%w: unknown organization: check --org: %w", config.ErrMachineConfig, err)
	case errors.Is(err, api.ErrMachineUnsupported):
		return fmt.Errorf("%w: the API does not support machine accounts: %w", config.ErrMachineConfig, err)
	case errors.As(err, &httpErr) && httpErr.Status == http.StatusForbidden:
		return fmt.Errorf("%w: the organization's plan does not include machine accounts: %w", config.ErrMachineConfig, err)
	}

	return err
}

// writeEnrollmentFile (re)writes enrollment.json atomically.
func writeEnrollmentFile(dir, id, org string, expires time.Time) error {
	data, err := json.MarshalIndent(config.EnrollmentInfo{Version: enrollFileVersion,
		EnrollmentID: id, OrganizationID: org, ExpiresAt: expires}, "", "  ")
	if err != nil {
		return err
	}

	return config.WriteMachineFile(dir, config.MachineEnrollmentFile, append(data, '\n'))
}

// loadOrCreateMachineKeys returns the signing key and the AGE recipient of the
// directory. Both files absent: generate and write them. Only one present: a
// configuration error (a half pair is never completed). Present keys are
// never touched.
func loadOrCreateMachineKeys(dir string) (*ecdsa.PrivateKey, string, bool, error) {
	sigPath := filepath.Join(dir, config.MachineSigningKeyFile)
	agePath := filepath.Join(dir, config.MachineAgeKeyFile)
	hasSig, err := fileExists(sigPath)
	if err != nil {
		return nil, "", false, err
	}
	hasAge, err := fileExists(agePath)
	if err != nil {
		return nil, "", false, err
	}
	switch {
	case hasSig != hasAge:
		return nil, "", false, fmt.Errorf("%w: %s and %s must both exist or both be absent",
			config.ErrMachineConfig, config.MachineSigningKeyFile, config.MachineAgeKeyFile)
	case !hasSig:
		k, r, err := generateMachineKeys(dir)

		return k, r, err == nil, err
	}

	sigPEM, err := config.ReadMachineFile(sigPath)
	if err != nil {
		return nil, "", false, err
	}
	sigKey, err := machinekey.ParseSigningKey(sigPEM)
	if err != nil {
		return nil, "", false, fmt.Errorf("%w: %s is not a valid ES256 key", config.ErrMachineConfig, sigPath)
	}
	ageData, err := config.ReadMachineFile(agePath)
	if err != nil {
		return nil, "", false, err
	}
	identity, err := parseMachineAgeKey(ageData, agePath)
	if err != nil {
		return nil, "", false, err
	}

	return sigKey, identity.Recipient().String(), false, nil
}

// requireMachineKeys fails unless both key files exist.
func requireMachineKeys(dir string) error {
	for _, name := range []string{config.MachineSigningKeyFile, config.MachineAgeKeyFile} {
		ok, err := fileExists(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: %s exists but %s is missing", config.ErrMachineConfig, config.MachineFile, name)
		}
	}

	return nil
}

// generateMachineKeys creates and stores both keys (0600).
func generateMachineKeys(dir string) (*ecdsa.PrivateKey, string, error) {
	sigKey, err := machinekey.GenerateSigningKey()
	if err != nil {
		return nil, "", fmt.Errorf("generating the signing key: %w", err)
	}
	sigPEM, err := machinekey.MarshalSigningKey(sigKey)
	if err != nil {
		return nil, "", err
	}
	identity, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, "", err
	}
	if err := config.WriteMachineFile(dir, config.MachineSigningKeyFile, sigPEM); err != nil {
		return nil, "", err
	}
	if err := config.WriteMachineFile(dir, config.MachineAgeKeyFile, []byte(identity.String()+"\n")); err != nil {
		// No API call was made with this pair yet: drop the signing key rather
		// than leave a half pair that every later run refuses.
		_ = os.Remove(filepath.Join(dir, config.MachineSigningKeyFile))

		return nil, "", err
	}

	return sigKey, identity.Recipient().String(), nil
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}

	return false, fmt.Errorf("%w: %s: %w", config.ErrMachineConfig, path, err)
}

// sleepCtx waits d or until ctx is done.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
