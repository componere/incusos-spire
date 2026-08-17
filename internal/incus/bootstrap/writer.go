package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/componere/incusos-spire/internal/attestor"
)

const (
	// ConfigKey is the only instance config key this adapter may ever write.
	// Every other key, and every volatile.* key above all, is refused locally.
	ConfigKey = "user.spiffe-bootstrap"
	// redactedMarker replaces the bootstrap payload wherever Incus echoes it
	// back inside an error string.
	redactedMarker = "[redacted]"

	// instancesPath is the Incus instance collection.
	instancesPath = "/1.0/instances"
	// operationsPath is the Incus operation collection.
	operationsPath = "/1.0/operations"
	// waitSegment is the operation sub-resource that blocks until the operation
	// reaches a final state.
	waitSegment = "wait"
	// asyncType marks an Incus envelope that carries a background operation
	// instead of a result.
	asyncType = "async"
	// httpsScheme is the only URL scheme this adapter dials.
	httpsScheme = "https"

	// maxAttempts is the bounded retry budget for transient transport faults
	// (E3). Retrying is safe because setting one config key to one value is
	// idempotent.
	maxAttempts = 3
	// maxBodyBytes caps a single Incus response.
	maxBodyBytes = 1 << 20
	// bodyOverread is one byte past maxBodyBytes so truncation is detectable.
	bodyOverread = maxBodyBytes + 1
	// sha256HexLength is the length of a SHA-256 fingerprint in hex.
	sha256HexLength = 64
	// maxInstanceNameLength is the documented Incus instance-name limit.
	maxInstanceNameLength = 63
	// operationSuccess is the Incus operation status code for a completed
	// operation.
	operationSuccess = 200
	// operationFailure is the lowest Incus operation status code that reports a
	// failed or cancelled operation.
	operationFailure = 400
	// minWaitSeconds is the shortest operation wait the adapter asks Incus for.
	minWaitSeconds = 1
)

// sentinelError is a comparable sentinel used with [errors.Is].
type sentinelError string

// Error returns the sentinel's stable message.
func (e sentinelError) Error() string {
	return string(e)
}

const (
	// ErrKeyNotAllowed is returned when a config key other than [ConfigKey]
	// reaches the write path. The refusal happens before a request is built, so
	// nothing is sent. It is defence in depth: the deployed credential can
	// technically write any key, and this adapter refuses to be the thing that
	// does.
	ErrKeyNotAllowed sentinelError = "bootstrap: config key is outside the write allowlist"
	// ErrInvalidTarget is returned when the instance name is empty, too long,
	// or outside the documented Incus instance-name character set. A rejected
	// name can never re-target the request path.
	ErrInvalidTarget sentinelError = "bootstrap: invalid write target"
	// ErrEmptyPayload is returned by [Writer.WriteBootstrap] for an empty
	// payload, because Incus treats an empty value as a key removal and the
	// caller would silently clear the binding instead of creating it.
	ErrEmptyPayload sentinelError = "bootstrap: empty bootstrap payload"
	// errPinMismatch reports that the peer's leaf certificate did not match the
	// configured SHA-256 pin. It is a deployment fault, so a write that fails on
	// it is permanent rather than transient.
	errPinMismatch sentinelError = "bootstrap: server certificate does not match the configured pin"
)

// httpDoer is the subset of [http.Client] used for the bootstrap write.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config is the explicit connection material for the bootstrap writer. Every
// field is required except that exactly one of ServerCertPEMPath and
// ServerCertFingerprint must pin the server.
type Config struct {
	// ServerURL is the Incus HTTPS origin (scheme://host:port), with no /1.0
	// prefix. HTTP and Unix sockets are rejected.
	ServerURL string
	// ClientCertPEMPath is the path to the bootstrap-writer client certificate
	// PEM. This credential must be the write-only identity, never the attestor's
	// read-only one; the separation is a deployment invariant enforced by the
	// Incus authorization policy, not by this package.
	ClientCertPEMPath string
	// ClientKeyPEMPath is the path to the matching client private key PEM.
	ClientKeyPEMPath string
	// ServerCertPEMPath is the path to the Incus server certificate PEM used as
	// a trust anchor. Empty when ServerCertFingerprint is set.
	ServerCertPEMPath string
	// ServerCertFingerprint is the SHA-256 hex fingerprint of the Incus server
	// certificate, matching environment.certificate_fingerprint. Empty when
	// ServerCertPEMPath is set.
	ServerCertFingerprint string
	// DefaultProject is the project used when a call passes an empty project
	// name.
	DefaultProject attestor.ProjectName
	// RequestTimeout bounds every Incus call, including retries and any
	// operation wait.
	RequestTimeout time.Duration
}

// Writer sets and clears user.spiffe-bootstrap on one Incus instance.
//
// It holds the write-only bootstrap credential and issues one raw PATCH per
// call. It performs no instance read, so it cannot resolve a UUID to a name;
// the caller supplies the name it resolved through the read-only adapter.
type Writer struct {
	// base is the Incus HTTPS origin.
	base *url.URL
	// doer performs requests with the configured client certificate.
	doer httpDoer
	// defaultProject is used when the caller omits a project.
	defaultProject attestor.ProjectName
	// timeout is the per-call bound applied on top of the caller's context.
	timeout time.Duration
}

// NewWriter validates cfg and returns a concrete [Writer].
//
// NewWriter does not dial Incus. TLS material is loaded and pinned here so a
// misconfiguration fails before the first bootstrap write.
func NewWriter(cfg Config) (*Writer, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	base, err := url.Parse(strings.TrimRight(strings.TrimSpace(cfg.ServerURL), "/"))
	if err != nil {
		return nil, fmt.Errorf("parse server URL: %w", err)
	}

	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	return &Writer{
		base:           base,
		doer:           &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}},
		defaultProject: cfg.DefaultProject,
		timeout:        cfg.RequestTimeout,
	}, nil
}

// WriteBootstrap sets user.spiffe-bootstrap on one instance with a single raw
// PATCH.
//
// payload is a secret. It is never logged and never formatted into an error;
// server text that echoes it is redacted. An empty payload is
// [ErrEmptyPayload], because Incus removes a key set to an empty value and the
// caller would clear the binding instead of writing it; use
// [Writer.ClearBootstrap] for that. An empty project uses the configured
// default.
//
// name must be the name the caller just resolved from the instance UUID
// through the read-only adapter: names are reusable after delete and recreate,
// so a stale name writes the secret into a different instance.
func (writer *Writer) WriteBootstrap(
	ctx context.Context,
	project attestor.ProjectName,
	name attestor.InstanceName,
	payload string,
) error {
	if payload == "" {
		return fmt.Errorf("%w: use ClearBootstrap to remove the key", ErrEmptyPayload)
	}

	return writer.patchConfig(ctx, project, name, ConfigKey, payload)
}

// ClearBootstrap removes user.spiffe-bootstrap from one instance with a single
// raw PATCH that sets the key to an empty value. P5 verified live that Incus
// drops the key rather than storing an empty string: after a clear,
// .config has("user.spiffe-bootstrap") is false.
//
// The redemption path clears after it commits the consumption and so may clear
// twice after a crash. Nothing here treats a repeat as special: the same PATCH
// is sent again. That differs from "incus config unset", which fails on an
// absent key, but that path is a read-modify-write this credential cannot
// perform anyway.
func (writer *Writer) ClearBootstrap(
	ctx context.Context,
	project attestor.ProjectName,
	name attestor.InstanceName,
) error {
	return writer.patchConfig(ctx, project, name, ConfigKey, "")
}

// patchConfig sends exactly one config key in exactly one PATCH request, then
// retries only a transient transport fault, within maxAttempts.
//
// key is checked against the allowlist first, so a caller that arrives with
// volatile.uuid or any other key leaves without touching the network. value is
// treated as secret from here down.
func (writer *Writer) patchConfig(
	ctx context.Context,
	project attestor.ProjectName,
	name attestor.InstanceName,
	key string,
	value string,
) error {
	if key != ConfigKey {
		return fmt.Errorf("%w: %q", ErrKeyNotAllowed, key)
	}

	target, err := writer.targetURL(project, name)
	if err != nil {
		return err
	}

	body, err := json.Marshal(configPatch{Config: map[string]string{key: value}})
	if err != nil {
		// Unreachable for a map of strings. The underlying error is dropped
		// rather than wrapped because the value is the only thing it could
		// quote.
		return wrapPermanent(errors.New("encode PATCH body"))
	}

	ctx, cancel := context.WithTimeout(ctx, writer.timeout)
	defer cancel()

	var last error
	for range maxAttempts {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return classifyTransport(ctxErr)
		}

		last = writer.patchOnce(ctx, target, body, value)
		if last == nil {
			return nil
		}
		if !errors.Is(last, attestor.ErrBackendUnavailable) {
			return last
		}
	}

	return last
}

// patchOnce performs one PATCH and, only if Incus answered with a background
// operation, waits for that operation to reach a final state.
func (writer *Writer) patchOnce(ctx context.Context, target string, body []byte, secret string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, target, bytes.NewReader(body))
	if err != nil {
		return wrapPermanent(errors.New("build PATCH request"))
	}
	req.Header.Set("Content-Type", "application/json")

	envelope, err := writer.roundTrip(req, secret)
	if err != nil {
		return err
	}

	return writer.awaitOperation(ctx, envelope, secret)
}

// roundTrip performs one request and decodes the Incus envelope. Every failure
// leaves with a retry class: [attestor.ErrBackendUnauthorized] for an Incus
// credential refusal, [attestor.ErrBackendPermanent] for a response this
// adapter can never accept, and [attestor.ErrBackendUnavailable] for a
// transient transport fault.
//
// The body is decoded before the status is judged, so a refusal carries the
// Incus explanation ("Permission denied", "Instance not found") instead of a
// bare status code. That text is redacted first: a response body is the one
// place where the server can echo submitted content back at us.
func (writer *Writer) roundTrip(req *http.Request, secret string) (apiEnvelope, error) {
	resp, err := writer.doer.Do(req)
	if err != nil {
		return apiEnvelope{}, classifyTransport(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, bodyOverread))
	if err != nil {
		return apiEnvelope{}, classifyTransport(err)
	}
	if len(raw) > maxBodyBytes {
		return apiEnvelope{}, wrapPermanent(fmt.Errorf("response exceeded %d bytes", maxBodyBytes))
	}

	var envelope apiEnvelope
	decodeErr := json.Unmarshal(raw, &envelope)
	detail := incusDetail(envelope, secret)

	switch {
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		return apiEnvelope{}, wrapUnauthorized(
			fmt.Errorf("authorization failed: HTTP %d%s", resp.StatusCode, detail),
		)
	case resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted:
		return apiEnvelope{}, wrapPermanent(fmt.Errorf("unexpected HTTP %d%s", resp.StatusCode, detail))
	case decodeErr != nil:
		return apiEnvelope{}, wrapPermanent(
			fmt.Errorf("decode Incus envelope: %s", scrub(decodeErr.Error(), secret)),
		)
	case envelope.Error != "" || envelope.ErrorCode != 0:
		return apiEnvelope{}, wrapPermanent(fmt.Errorf("incus error %d%s", envelope.ErrorCode, detail))
	default:
		return envelope, nil
	}
}

// incusDetail returns the redacted Incus error text as a message suffix, or an
// empty string when the response carried none.
func incusDetail(envelope apiEnvelope, secret string) string {
	text := scrub(strings.TrimSpace(envelope.Error), secret)
	if text == "" {
		return ""
	}

	return ": " + text
}

// awaitOperation accepts the synchronous empty answer Incus 7.3 gives an
// instance PATCH, and otherwise waits out the background operation rather than
// reporting a write that may still fail.
func (writer *Writer) awaitOperation(ctx context.Context, envelope apiEnvelope, secret string) error {
	if envelope.Type != asyncType && envelope.Operation == "" {
		return nil
	}

	id := operationID(envelope)
	if id == "" {
		return wrapPermanent(errors.New("async response carried no operation id"))
	}

	operation, err := writer.waitOperation(ctx, id, secret)
	if err != nil {
		return err
	}

	status := scrub(operation.Status, secret)
	switch {
	case operation.Err != "":
		return wrapPermanent(fmt.Errorf("incus operation failed: %s", scrub(operation.Err, secret)))
	case operation.StatusCode == operationSuccess:
		return nil
	case operation.StatusCode >= operationFailure:
		return wrapPermanent(fmt.Errorf("incus operation ended %s (%d)", status, operation.StatusCode))
	default:
		return wrapTransient(fmt.Errorf("incus operation still %s after the bounded wait", status))
	}
}

// waitOperation blocks on the operation until it settles or the remaining
// request timeout expires. It is the only GET this package can issue, it
// returns operation status rather than instance data, and Incus authorizes it
// on being a trusted client, so it works for a read-denied credential.
func (writer *Writer) waitOperation(ctx context.Context, id string, secret string) (operationPayload, error) {
	endpoint := writer.base.JoinPath(operationsPath, url.PathEscape(id), waitSegment)
	query := url.Values{}
	query.Set("timeout", strconv.Itoa(waitSeconds(ctx)))
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return operationPayload{}, wrapPermanent(errors.New("build operation wait request"))
	}

	envelope, err := writer.roundTrip(req, secret)
	if err != nil {
		return operationPayload{}, err
	}

	var operation operationPayload
	if err := json.Unmarshal(envelope.Metadata, &operation); err != nil {
		return operationPayload{}, wrapPermanent(fmt.Errorf("decode Incus operation: %s", scrub(err.Error(), secret)))
	}

	return operation, nil
}

// targetURL builds the instance endpoint for one PATCH. The instance name is
// validated rather than escaped away, so a name that could re-target the
// request never reaches the URL.
func (writer *Writer) targetURL(project attestor.ProjectName, name attestor.InstanceName) (string, error) {
	if err := validateInstanceName(name); err != nil {
		return "", err
	}

	if strings.TrimSpace(string(project)) == "" {
		project = writer.defaultProject
	}

	endpoint := writer.base.JoinPath(instancesPath, string(name))
	query := url.Values{}
	query.Set("project", string(project))
	endpoint.RawQuery = query.Encode()

	return endpoint.String(), nil
}

// configPatch is the PATCH body: one config key, nothing else. Incus merges it
// into the stored config server-side, which is what makes the write possible
// without a client read.
type configPatch struct {
	// Config is the single-entry config map sent to Incus.
	Config map[string]string `json:"config"`
}

// apiEnvelope is the Incus REST envelope. An instance PATCH answers with the
// sync form and an empty metadata object.
type apiEnvelope struct {
	// Type is "sync" or "async".
	Type string `json:"type"`
	// Status is the human-readable Incus status.
	Status string `json:"status"`
	// StatusCode is the Incus status code.
	StatusCode int `json:"status_code"`
	// Operation is the operation URL on an async answer.
	Operation string `json:"operation"`
	// ErrorCode is non-zero when Incus reports a protocol error.
	ErrorCode int `json:"error_code"`
	// Error is the Incus error text. It can echo submitted content, so it is
	// redacted before it reaches an error.
	Error string `json:"error"`
	// Metadata is the unwrapped payload: {} for a PATCH, the operation object
	// for an operation wait.
	Metadata json.RawMessage `json:"metadata"`
}

// operationPayload is the subset of the Incus operation object that decides
// whether the write happened.
type operationPayload struct {
	// ID is the operation UUID.
	ID string `json:"id"`
	// Status is the human-readable operation status.
	Status string `json:"status"`
	// StatusCode is 200 on success and 400 or above on failure or cancellation.
	StatusCode int `json:"status_code"`
	// Err is the operation's failure text, empty while it can still succeed.
	Err string `json:"err"`
}

// operationID prefers the operation object's own id and falls back to the last
// element of the operation URL in the envelope.
func operationID(envelope apiEnvelope) string {
	var operation operationPayload
	if len(envelope.Metadata) > 0 &&
		json.Unmarshal(envelope.Metadata, &operation) == nil &&
		operation.ID != "" {
		return operation.ID
	}

	trimmed := strings.TrimRight(envelope.Operation, "/")
	if trimmed == "" {
		return ""
	}

	id := path.Base(trimmed)
	if id == "." || id == "/" {
		return ""
	}

	return id
}

// waitSeconds bounds the Incus-side wait by what is left of this call's own
// deadline, so an operation wait can never outlive the configured request
// timeout.
func waitSeconds(ctx context.Context) int {
	deadline, ok := ctx.Deadline()
	if !ok {
		return minWaitSeconds
	}

	remaining := int(time.Until(deadline).Seconds())

	return max(remaining, minWaitSeconds)
}

// validateInstanceName enforces the documented Incus instance-name limits:
// 1 to 63 ASCII letters, digits, and dashes. The rule is deliberately weaker
// than the Incus one, which also forbids a leading digit or dash and a
// trailing dash, so it can never reject a name Incus accepted. It makes a
// snapshot name, a traversal, and an escape sequence impossible in the request
// path.
func validateInstanceName(name attestor.InstanceName) error {
	if len(name) == 0 || len(name) > maxInstanceNameLength {
		return fmt.Errorf(
			"%w: instance name must be 1 to %d characters",
			ErrInvalidTarget,
			maxInstanceNameLength,
		)
	}

	for _, char := range name {
		switch {
		case char >= 'a' && char <= 'z',
			char >= 'A' && char <= 'Z',
			char >= '0' && char <= '9',
			char == '-':
			continue
		default:
			return fmt.Errorf("%w: instance name %q is not a valid Incus instance name", ErrInvalidTarget, name)
		}
	}

	return nil
}

// scrub removes the bootstrap payload from server-supplied text.
//
// Appendix D forbids a nonce value in any log or error, and an Incus error
// envelope can quote submitted content, so every string this package takes out
// of a response passes through here before it can become part of an error.
func scrub(text string, secret string) string {
	if secret == "" {
		return text
	}

	return strings.ReplaceAll(text, secret, redactedMarker)
}

// validateConfig fails closed on missing TLS material, project, or timeout,
// before anything is loaded from disk.
func validateConfig(cfg Config) error {
	pinnedByPEM := strings.TrimSpace(cfg.ServerCertPEMPath) != ""
	pinnedByFingerprint := strings.TrimSpace(cfg.ServerCertFingerprint) != ""

	required := []struct {
		satisfied bool
		message   string
	}{
		{strings.TrimSpace(cfg.ServerURL) != "", "ServerURL is required"},
		{strings.TrimSpace(cfg.ClientCertPEMPath) != "", "ClientCertPEMPath is required"},
		{strings.TrimSpace(cfg.ClientKeyPEMPath) != "", "ClientKeyPEMPath is required"},
		{strings.TrimSpace(string(cfg.DefaultProject)) != "", "DefaultProject is required"},
		{cfg.RequestTimeout > 0, "RequestTimeout must be positive"},
		{
			pinnedByPEM != pinnedByFingerprint,
			"exactly one of ServerCertPEMPath and ServerCertFingerprint is required",
		},
	}
	for _, check := range required {
		if !check.satisfied {
			return errors.New(check.message)
		}
	}

	if err := validateServerURL(cfg.ServerURL); err != nil {
		return err
	}
	if pinnedByFingerprint {
		if err := validateFingerprint(cfg.ServerCertFingerprint); err != nil {
			return err
		}
	}

	for _, material := range materialPaths(cfg) {
		if _, err := os.Stat(material); err != nil {
			return fmt.Errorf("stat %s: %w", material, err)
		}
	}

	return nil
}

// validateServerURL rejects anything that is not an HTTPS origin.
func validateServerURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("parse server URL: %w", err)
	}
	if parsed.Scheme != httpsScheme || parsed.Host == "" {
		return fmt.Errorf("ServerURL must be an https origin, got %q", raw)
	}

	return nil
}

// materialPaths returns the PEM paths that must exist on disk.
func materialPaths(cfg Config) []string {
	paths := []string{cfg.ClientCertPEMPath, cfg.ClientKeyPEMPath}
	if strings.TrimSpace(cfg.ServerCertPEMPath) != "" {
		paths = append(paths, cfg.ServerCertPEMPath)
	}

	return paths
}

// validateFingerprint checks a SHA-256 hex pin.
func validateFingerprint(raw string) error {
	normalized := normalizeFingerprint(raw)
	if len(normalized) != sha256HexLength {
		return fmt.Errorf("ServerCertFingerprint must be %d hex characters", sha256HexLength)
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return fmt.Errorf("ServerCertFingerprint is not hex: %w", err)
	}

	return nil
}

// buildTLSConfig loads the bootstrap-writer certificate and pins the server.
func buildTLSConfig(cfg Config) (*tls.Config, error) {
	clientCert, err := tls.LoadX509KeyPair(cfg.ClientCertPEMPath, cfg.ClientKeyPEMPath)
	if err != nil {
		return nil, fmt.Errorf("load client certificate: %w", err)
	}

	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{clientCert},
	}

	if strings.TrimSpace(cfg.ServerCertPEMPath) != "" {
		pool, err := serverTrustPool(cfg.ServerCertPEMPath)
		if err != nil {
			return nil, err
		}
		tlsCfg.RootCAs = pool

		return tlsCfg, nil
	}

	// The fingerprint pin is the trust root, so chain verification is replaced
	// by the pin rather than merely skipped.
	tlsCfg.InsecureSkipVerify = true
	applyPin(tlsCfg, normalizeFingerprint(cfg.ServerCertFingerprint))

	return tlsCfg, nil
}

// serverTrustPool reads the first CERTIFICATE block of a PEM file into a trust
// pool.
func serverTrustPool(pemPath string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(pemPath)
	if err != nil {
		return nil, fmt.Errorf("read server certificate: %w", err)
	}

	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("server certificate PEM has no CERTIFICATE block")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse server certificate: %w", err)
		}

		pool := x509.NewCertPool()
		pool.AddCert(cert)

		return pool, nil
	}
}

// applyPin installs the leaf SHA-256 pin on both TLS verification hooks.
// VerifyConnection is needed as well as VerifyPeerCertificate because a
// resumed TLS session presents no certificate chain to verify.
func applyPin(tlsCfg *tls.Config, pin string) {
	tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		return matchPin(pin, rawCerts)
	}
	tlsCfg.VerifyConnection = func(state tls.ConnectionState) error {
		rawCerts := make([][]byte, len(state.PeerCertificates))
		for index, cert := range state.PeerCertificates {
			rawCerts[index] = cert.Raw
		}

		return matchPin(pin, rawCerts)
	}
}

// matchPin compares the SHA-256 of the presented leaf certificate to pin.
func matchPin(pin string, rawCerts [][]byte) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("%w: peer presented no certificate", errPinMismatch)
	}

	sum := sha256.Sum256(rawCerts[0])
	got := hex.EncodeToString(sum[:])
	if got != pin {
		return fmt.Errorf("%w: got %s", errPinMismatch, got)
	}

	return nil
}

// normalizeFingerprint lowercases hex and strips colons and whitespace.
func normalizeFingerprint(raw string) string {
	trimmed := strings.TrimSpace(raw)
	trimmed = strings.ReplaceAll(trimmed, ":", "")
	trimmed = strings.ReplaceAll(trimmed, " ", "")

	return strings.ToLower(trimmed)
}

// classifyTransport maps a transport failure onto the backend error contract.
// Only a recognized transient fault stays retryable, because a fault reported
// as transient is retried here and again by the caller, which turns one
// misconfiguration into many writes.
func classifyTransport(err error) error {
	if isTransient(err) {
		return wrapTransient(err)
	}

	return wrapPermanent(err)
}

// isTransient reports the transport faults a bounded retry can plausibly clear
// (E3): a refused, reset, or aborted connection, an unreachable peer, a
// truncated response, and a deadline or cancellation. A TLS or certificate
// fault never qualifies: only an operator can clear it.
func isTransient(err error) bool {
	switch {
	case err == nil, isTLSFault(err):
		return false
	case errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, context.Canceled),
		errors.Is(err, os.ErrDeadlineExceeded):
		return true
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return true
	case errors.Is(err, syscall.ECONNRESET),
		errors.Is(err, syscall.ECONNABORTED),
		errors.Is(err, syscall.ECONNREFUSED),
		errors.Is(err, syscall.EHOSTUNREACH),
		errors.Is(err, syscall.ENETUNREACH),
		errors.Is(err, syscall.EPIPE):
		return true
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsTemporary || dnsErr.IsTimeout
	}

	var netErr net.Error

	return errors.As(err, &netErr) && netErr.Timeout()
}

// isTLSFault reports a handshake outcome only an operator can fix: a leaf that
// fails the configured pin, a chain that fails verification, or a peer that
// does not speak TLS.
func isTLSFault(err error) bool {
	var verifyErr *tls.CertificateVerificationError
	var recordErr tls.RecordHeaderError
	var hostErr x509.HostnameError

	return errors.Is(err, errPinMismatch) ||
		errors.As(err, &verifyErr) ||
		errors.As(err, &recordErr) ||
		errors.As(err, &hostErr)
}

// wrapTransient marks err as a retryable backend outage.
func wrapTransient(err error) error {
	return wrapSentinel(attestor.ErrBackendUnavailable, err)
}

// wrapUnauthorized marks err as an Incus credential refusal that must not be
// retried.
func wrapUnauthorized(err error) error {
	return wrapSentinel(attestor.ErrBackendUnauthorized, err)
}

// wrapPermanent marks err as a protocol or configuration fault that must not be
// retried.
func wrapPermanent(err error) error {
	return wrapSentinel(attestor.ErrBackendPermanent, err)
}

// wrapSentinel attaches sentinel to err unless err is already classified, so a
// failure keeps the class the innermost layer gave it.
func wrapSentinel(sentinel error, err error) error {
	switch {
	case err == nil:
		return sentinel
	case errors.Is(err, attestor.ErrBackendUnavailable),
		errors.Is(err, attestor.ErrBackendUnauthorized),
		errors.Is(err, attestor.ErrBackendPermanent):
		return err
	default:
		return fmt.Errorf("%w: %w", sentinel, err)
	}
}
