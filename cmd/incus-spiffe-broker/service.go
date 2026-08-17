package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/componere/incusos-spire/internal/attestor"
	"github.com/componere/incusos-spire/internal/nonce"
)

const (
	// mintPath is the operator endpoint that provisions one guest.
	mintPath = "/v1alpha1/nonce"
	// redeemPath is the guest endpoint that redeems a bootstrap value.
	redeemPath = "/v1alpha1/redeem"
	// maxRequestBytes caps a request body. Both documents are a handful of
	// short strings, so anything larger is a mistake or an attack.
	maxRequestBytes = 4096
	// contentTypeJSON is the media type of every answer, including failures.
	contentTypeJSON = "application/json"
)

const (
	// codeInvalidRequest names a request this service could not parse.
	codeInvalidRequest = "invalid_request"
	// codeUnauthorized names a refused nonce presentation. It is the single
	// code for an unknown nonce and for a wrong secret alike, so the answer
	// cannot be used to enumerate live nonce IDs.
	codeUnauthorized = "unauthorized"
	// codeConflict names a nonce or instance state that cannot be redeemed:
	// expired, already used, bound elsewhere, or rolled back.
	codeConflict = "conflict"
	// codeMethodNotAllowed names a request method other than POST.
	codeMethodNotAllowed = "method_not_allowed"
	// codeInternal names a fault an operator must fix.
	codeInternal = "internal"
	// codeUnavailable names a transient fault a caller may retry.
	codeUnavailable = "unavailable"
)

const (
	// operationMint labels the operator path in log records.
	operationMint = "mint"
	// operationRedeem labels the guest path in log records.
	operationRedeem = "redeem"
)

// bindingLookup is the slice of the nonce store this service reads directly: it
// answers "which instance is this nonce bound to" before anything is resolved
// or consumed. It is a lookup, never a redemption path;
// [nonce.Minter.Redeem] performs the atomic consume.
type bindingLookup interface {
	// Get returns the stored record for id without consuming it.
	Get(ctx context.Context, id nonce.NonceID) (nonce.Record, error)
}

// nonceMinter is the port into the nonce lifecycle core. The service owns no
// lifecycle rules of its own; it translates HTTP into a core call and the core
// answer into an HTTP answer.
type nonceMinter interface {
	// Mint issues a nonce bound to one instance UUID plus one generation and
	// writes the bootstrap payload onto the named instance.
	Mint(
		ctx context.Context,
		project attestor.ProjectName,
		name attestor.InstanceName,
		uuid attestor.InstanceUUID,
		generation attestor.GenerationUUID,
	) (nonce.Issued, error)
	// Redeem consumes the nonce and confirms it is bound to live, the record
	// the read path resolved independently.
	Redeem(
		ctx context.Context,
		id nonce.NonceID,
		secret nonce.Secret,
		live attestor.InstanceRecord,
	) (nonce.Record, error)
	// Clear empties the bootstrap configuration key. It runs after a
	// redemption commits, never before.
	Clear(ctx context.Context, project attestor.ProjectName, name attestor.InstanceName) error
}

// selectorDeriver is the port into the pure selector core. The service does not
// derive selectors and does not know the trust rules behind them.
type selectorDeriver interface {
	// Derive returns the frozen selector set for the referenced instance.
	Derive(ctx context.Context, ref attestor.Reference) ([]attestor.Selector, error)
}

// mintRequest is the operator request body. project is optional and defaults to
// the read adapter's configured project.
type mintRequest struct {
	// InstanceUUID is the volatile.uuid of the instance to provision. It is the
	// only identity anchor a caller may supply, and it is resolved through the
	// read path rather than trusted.
	InstanceUUID string `json:"instance_uuid"`
	// Project scopes the lookup. Empty means the configured default project.
	Project string `json:"project"`
}

// mintResponse is the operator answer.
//
// It has no secret field, by design. The nonce secret reaches exactly one
// destination, the guest-readable instance configuration key, so possession of
// it is evidence of a read from inside the bound instance. Returning it here
// would create a second copy of a bearer credential in every place an operator
// response can be recorded.
type mintResponse struct {
	// NonceID is the public identifier the guest presents at redemption.
	NonceID nonce.NonceID `json:"nonce_id"`
	// ExpiresAt is the instant the nonce stops being redeemable.
	ExpiresAt time.Time `json:"expires_at"`
	// InstanceUUID is the resolved volatile.uuid the nonce is bound to.
	InstanceUUID attestor.InstanceUUID `json:"instance_uuid"`
	// InstanceName is the name freshly resolved from the UUID and used as the
	// write address. It is reported so an operator can confirm which instance
	// received the key.
	InstanceName attestor.InstanceName `json:"instance_name"`
	// Generation is the bound volatile.uuid.generation. A snapshot restore
	// replaces it and invalidates the nonce.
	Generation attestor.GenerationUUID `json:"generation"`
	// Project is the resolved project of the bound instance.
	Project attestor.ProjectName `json:"project"`
}

// redeemRequest is the guest request body: the two secret-bearing fields of the
// bootstrap payload as the guest read them out of user.spiffe-bootstrap.
//
// Unknown fields are ignored so a guest may forward the payload document
// verbatim. An instance_uuid a caller adds is therefore accepted and ignored;
// the binding is resolved server-side from the nonce record.
type redeemRequest struct {
	// NonceID is the public nonce identifier.
	NonceID string `json:"nonce_id"`
	// Nonce is the presented secret. It is converted to a [nonce.Secret]
	// immediately after decoding and this field is zeroed, so the raw material
	// has the shortest possible life. [redeemRequest.LogValue] and
	// [redeemRequest.String] redact it in the meantime.
	Nonce string `json:"nonce"`
}

// String redacts the request. It satisfies [fmt.Stringer] so that %v and %s on
// a decoded request cannot print the presented secret.
func (r redeemRequest) String() string {
	return "redeemRequest(nonce_id=" + r.NonceID + ", nonce=" + nonce.RedactedSecret + ")"
}

// LogValue redacts the request for [log/slog]. It satisfies
// [log/slog.LogValuer] so that structured logging cannot record the presented
// secret.
func (r redeemRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("nonce_id", r.NonceID),
		slog.String("nonce", nonce.RedactedSecret),
	)
}

// redeemResponse is the guest answer on a successful redemption.
//
// P9 replaces this body with an exchange SVID: the guest will receive
// credential material instead of a description of the identity it proved. The
// selector list is the P8 observable, and it is secret-free.
type redeemResponse struct {
	// NonceID echoes the consumed nonce identifier.
	NonceID nonce.NonceID `json:"nonce_id"`
	// InstanceUUID is the bound volatile.uuid, resolved server-side.
	InstanceUUID attestor.InstanceUUID `json:"instance_uuid"`
	// InstanceName is the live name of the bound instance.
	InstanceName attestor.InstanceName `json:"instance_name"`
	// Generation is the live volatile.uuid.generation that matched the binding.
	Generation attestor.GenerationUUID `json:"generation"`
	// Project is the project of the bound instance.
	Project attestor.ProjectName `json:"project"`
	// Selectors are the frozen incus: selectors derived for the bound instance.
	Selectors []attestor.Selector `json:"selectors"`
}

// errorResponse is the uniform failure body. It names the status class and
// never the cause, so no answer distinguishes an unknown nonce from a wrong
// secret.
type errorResponse struct {
	// Error is one of the code constants of this package.
	Error string `json:"error"`
}

// ServiceConfig carries the collaborators of a [Service]. Every field is
// required; composition happens in main.
type ServiceConfig struct {
	// Reader is the read-only Incus identity path. It resolves a UUID to the
	// live instance record and is the only source of an instance name.
	Reader attestor.InstanceReader
	// Bindings answers which instance a nonce is bound to.
	Bindings bindingLookup
	// Minter runs the nonce lifecycle over the store and the bootstrap writer.
	Minter nonceMinter
	// Deriver produces the frozen selector set for a redeemed instance.
	Deriver selectorDeriver
	// Logger receives every mint and every redemption decision.
	Logger *slog.Logger
}

// Service serves the two bootstrap endpoints. It holds no mutable state: the
// nonce state lives in the store behind the minter.
type Service struct {
	// reader resolves a UUID to the live instance record.
	reader attestor.InstanceReader
	// bindings answers which instance a nonce is bound to.
	bindings bindingLookup
	// minter runs the nonce lifecycle.
	minter nonceMinter
	// deriver produces the frozen selector set.
	deriver selectorDeriver
	// logger receives every decision this service makes.
	logger *slog.Logger
}

// NewService validates cfg and returns a concrete [Service].
//
// A missing collaborator is a composition error and is reported here, before
// the listener opens, rather than as a nil dereference on the first request.
func NewService(cfg ServiceConfig) (*Service, error) {
	switch {
	case cfg.Reader == nil:
		return nil, errors.New("broker: service requires an instance reader")
	case cfg.Bindings == nil:
		return nil, errors.New("broker: service requires a nonce binding lookup")
	case cfg.Minter == nil:
		return nil, errors.New("broker: service requires a nonce minter")
	case cfg.Deriver == nil:
		return nil, errors.New("broker: service requires a selector deriver")
	case cfg.Logger == nil:
		return nil, errors.New("broker: service requires a logger")
	}

	return &Service{
		reader:   cfg.Reader,
		bindings: cfg.Bindings,
		minter:   cfg.Minter,
		deriver:  cfg.Deriver,
		logger:   cfg.Logger,
	}, nil
}

// Handler returns the routed HTTP surface: [mintPath] and [redeemPath], both
// POST only.
//
// The two routes are registered without a method pattern on purpose. The
// mux would answer a wrong method with its own plain-text 405, and every
// failure this service produces must carry the uniform JSON body.
func (s *Service) Handler() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc(mintPath, s.handleMint)
	mux.HandleFunc(redeemPath, s.handleRedeem)

	return mux
}

// handleMint provisions one guest: it resolves the requested UUID through the
// read path and mints a nonce against the freshly resolved instance name.
//
// The read is not optional and not cacheable. The bootstrap-writer credential
// is denied every read (P5), so it cannot resolve a UUID itself, and an Incus
// instance name is reusable after a delete and recreate (P6), so a name that
// was correct a minute ago can address a different instance now.
func (s *Service) handleMint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !s.requirePost(ctx, w, r, operationMint) {
		return
	}

	var request mintRequest
	if err := decodeRequest(w, r, &request); err != nil {
		s.refuse(ctx, w, operationMint, "", "", http.StatusBadRequest, codeInvalidRequest, err.Error())

		return
	}

	instanceUUID := attestor.InstanceUUID(strings.TrimSpace(request.InstanceUUID))
	if instanceUUID == "" {
		s.refuse(ctx, w, operationMint, "", "",
			http.StatusBadRequest, codeInvalidRequest, "instance_uuid is required")

		return
	}

	requested := attestor.ProjectName(strings.TrimSpace(request.Project))

	live, err := s.reader.ReadInstanceByUUID(ctx, instanceUUID, requested)
	if err != nil {
		s.deny(ctx, w, operationMint, "", instanceUUID, err)

		return
	}

	issued, err := s.minter.Mint(ctx, live.Project, live.Name, live.UUID, live.Generation)
	if err != nil {
		s.deny(ctx, w, operationMint, "", live.UUID, err)

		return
	}

	s.logger.InfoContext(ctx, "bootstrap nonce minted",
		"operation", operationMint,
		"nonce_id", issued.ID,
		"instance_uuid", live.UUID,
		"instance_name", live.Name,
		"generation", live.Generation,
		"project", live.Project,
		"expires_at", issued.ExpiresAt,
	)

	s.writeJSON(ctx, w, http.StatusCreated, mintResponse{
		NonceID:      issued.ID,
		ExpiresAt:    issued.ExpiresAt,
		InstanceUUID: live.UUID,
		InstanceName: live.Name,
		Generation:   live.Generation,
		Project:      live.Project,
	})
}

// handleRedeem consumes a nonce presented by a guest.
//
// The caller supplies a nonce ID and a secret and nothing else that matters.
// The bound UUID comes from the nonce record, the live instance record comes
// from the read path, and only then is the nonce consumed. A caller-claimed
// instance identity is ignored, which is what stops one guest from presenting
// its own valid nonce while asking for another instance's identity.
func (s *Service) handleRedeem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !s.requirePost(ctx, w, r, operationRedeem) {
		return
	}

	var request redeemRequest
	if err := decodeRequest(w, r, &request); err != nil {
		s.refuse(ctx, w, operationRedeem, "", "", http.StatusBadRequest, codeInvalidRequest, err.Error())

		return
	}

	id := nonce.NonceID(strings.TrimSpace(request.NonceID))
	secret := nonce.NewSecret(request.Nonce)
	request.Nonce = ""

	if secret.IsZero() {
		s.deny(ctx, w, operationRedeem, id, "",
			fmt.Errorf("%w: empty secret presentation", nonce.ErrSecretMismatch))

		return
	}

	record, err := s.bindings.Get(ctx, id)
	if err != nil {
		s.deny(ctx, w, operationRedeem, id, "", classifyLookup(id, err))

		return
	}

	live, err := s.reader.ReadInstanceByUUID(ctx, record.Instance, record.Project)
	if err != nil {
		s.deny(ctx, w, operationRedeem, id, record.Instance, err)

		return
	}

	consumed, err := s.minter.Redeem(ctx, id, secret, live)
	if err != nil {
		s.deny(ctx, w, operationRedeem, id, record.Instance, err)

		return
	}

	s.clearBootstrap(ctx, consumed.ID, live)

	selectors, err := s.deriver.Derive(ctx, attestor.Reference{
		InstanceUUID: consumed.Instance,
		Project:      consumed.Project,
		Generation:   consumed.Generation,
		Server:       "",
	})
	if err != nil {
		s.deny(ctx, w, operationRedeem, id, consumed.Instance, err)

		return
	}

	s.logger.InfoContext(ctx, "bootstrap nonce redeemed",
		"operation", operationRedeem,
		"outcome", "granted",
		"nonce_id", consumed.ID,
		"instance_uuid", consumed.Instance,
		"instance_name", live.Name,
		"generation", consumed.Generation,
		"project", consumed.Project,
		"http_status", http.StatusOK,
	)

	s.writeJSON(ctx, w, http.StatusOK, redeemResponse{
		NonceID:      consumed.ID,
		InstanceUUID: consumed.Instance,
		InstanceName: live.Name,
		Generation:   consumed.Generation,
		Project:      consumed.Project,
		Selectors:    selectors,
	})
}

// clearBootstrap empties the bootstrap key after a redemption has committed.
//
// A failure here does not fail the redemption. The consume is already
// committed, so what remains in the instance configuration is a value that no
// longer redeems; reporting a failure would invite a retry that can only be
// refused as already used. The event is logged at error level so the live run
// records the leftover.
func (s *Service) clearBootstrap(ctx context.Context, id nonce.NonceID, live attestor.InstanceRecord) {
	if err := s.minter.Clear(ctx, live.Project, live.Name); err != nil {
		s.logger.ErrorContext(ctx, "bootstrap key not cleared after redemption committed",
			"operation", operationRedeem,
			"nonce_id", id,
			"instance_uuid", live.UUID,
			"instance_name", live.Name,
			"project", live.Project,
			"reason", err.Error(),
		)

		return
	}

	s.logger.InfoContext(ctx, "bootstrap key cleared",
		"operation", operationRedeem,
		"nonce_id", id,
		"instance_uuid", live.UUID,
		"instance_name", live.Name,
		"project", live.Project,
	)
}

// requirePost answers a non-POST request with the uniform 405 body and reports
// whether the caller may continue.
func (s *Service) requirePost(ctx context.Context, w http.ResponseWriter, r *http.Request, operation string) bool {
	if r.Method == http.MethodPost {
		return true
	}

	w.Header().Set("Allow", http.MethodPost)
	s.refuse(ctx, w, operation, "", "",
		http.StatusMethodNotAllowed, codeMethodNotAllowed, "method "+r.Method+" is not allowed")

	return false
}

// deny maps a core or adapter failure onto the documented status and answers
// with the uniform body. Every denial is logged with its reason, so the live
// run has a decision record for each case, and no reason ever carries secret
// material: the presented secret is a [nonce.Secret], which redacts itself.
func (s *Service) deny(
	ctx context.Context,
	w http.ResponseWriter,
	operation string,
	id nonce.NonceID,
	instanceUUID attestor.InstanceUUID,
	err error,
) {
	status, code := failureStatus(err)
	s.refuse(ctx, w, operation, id, instanceUUID, status, code, err.Error())
}

// refuse logs one refusal and writes the uniform body. A 5xx is a fault an
// operator must look at, so it is logged at error level; a 4xx is an expected
// answer and is logged at warn level.
func (s *Service) refuse(
	ctx context.Context,
	w http.ResponseWriter,
	operation string,
	id nonce.NonceID,
	instanceUUID attestor.InstanceUUID,
	status int,
	code string,
	reason string,
) {
	record := []any{
		"operation", operation,
		"outcome", "denied",
		"nonce_id", id,
		"instance_uuid", instanceUUID,
		"http_status", status,
		"code", code,
		"reason", reason,
	}

	if status >= http.StatusInternalServerError {
		s.logger.ErrorContext(ctx, "bootstrap request failed", record...)
	} else {
		s.logger.WarnContext(ctx, "bootstrap request denied", record...)
	}

	s.writeJSON(ctx, w, status, errorResponse{Error: code})
}

// writeJSON writes one JSON document with the given status. A write failure is
// logged and nothing else: the status line is already on the wire.
func (s *Service) writeJSON(ctx context.Context, w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(body); err != nil {
		s.logger.ErrorContext(ctx, "write response body", "http_status", status, "reason", err.Error())
	}
}

// decodeRequest reads one bounded JSON object into dest. The body limit is
// enforced with [net/http.MaxBytesReader], so an oversized body is refused
// instead of buffered.
func decodeRequest(w http.ResponseWriter, r *http.Request, dest any) error {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes)).Decode(dest); err != nil {
		return fmt.Errorf("decode request body: %w", err)
	}

	return nil
}

// classifyLookup separates a lifecycle answer from a store fault on the binding
// lookup. A store that already named the lifecycle outcome keeps its sentinel;
// anything else becomes [nonce.ErrStoreUnavailable], so a broken backend is
// never reported as a refused nonce.
func classifyLookup(id nonce.NonceID, err error) error {
	if errors.Is(err, nonce.ErrNonceNotFound) {
		return err
	}

	return fmt.Errorf("%w: look up nonce %s: %w", nonce.ErrStoreUnavailable, id, err)
}

// failureStatus maps a failure onto its documented status and code. The table
// is the one in the package documentation.
//
// The backend classes are matched before the store and writer wrappers on
// purpose: the lifecycle core wraps a writer failure in
// [nonce.ErrWriterUnavailable] while keeping the class the adapter gave it, so
// an Incus credential refusal must not be laundered into a 503 that invites a
// retry it can never survive.
func failureStatus(err error) (int, string) {
	switch {
	case errors.Is(err, nonce.ErrNonceNotFound), errors.Is(err, nonce.ErrSecretMismatch):
		return http.StatusUnauthorized, codeUnauthorized

	case errors.Is(err, nonce.ErrNonceExpired),
		errors.Is(err, nonce.ErrNonceAlreadyUsed),
		errors.Is(err, nonce.ErrInstanceMismatch),
		errors.Is(err, nonce.ErrGenerationChanged),
		errors.Is(err, attestor.ErrInstanceNotFound),
		errors.Is(err, attestor.ErrAmbiguousReference),
		errors.Is(err, attestor.ErrGenerationMismatch),
		errors.Is(err, attestor.ErrUnusableRecord):
		return http.StatusConflict, codeConflict

	case errors.Is(err, attestor.ErrInvalidReference):
		return http.StatusBadRequest, codeInvalidRequest

	case errors.Is(err, attestor.ErrBackendUnauthorized), errors.Is(err, attestor.ErrBackendPermanent):
		return http.StatusInternalServerError, codeInternal

	case errors.Is(err, attestor.ErrBackendUnavailable),
		errors.Is(err, nonce.ErrStoreUnavailable),
		errors.Is(err, nonce.ErrWriterUnavailable):
		return http.StatusServiceUnavailable, codeUnavailable

	default:
		return http.StatusInternalServerError, codeInternal
	}
}
