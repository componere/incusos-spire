package identity

import (
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
	"strings"
	"syscall"
	"time"

	"github.com/componere/incusos-spire/internal/attestor"
)

const (
	// instancesPath is the Incus collection used for UUID lookup.
	instancesPath = "/1.0/instances"
	// serverPath is the Incus endpoint that carries API identity.
	serverPath = "/1.0"
	// recursionLevel is the collection recursion that replaces URL pointers
	// with instance objects, exposing config.
	recursionLevel = "1"
	// uuidFilterPrefix is the OData filter verified live in P6.
	uuidFilterPrefix = "config.volatile.uuid eq "
	// httpsScheme is the only URL scheme this adapter dials.
	httpsScheme = "https"
	// maxAttempts is the bounded retry budget for transient transport errors (E3).
	maxAttempts = 3
	// maxBodyBytes caps a single Incus response.
	maxBodyBytes = 1 << 20
	// bodyOverread is one byte past maxBodyBytes so a truncated read can be detected.
	bodyOverread = maxBodyBytes + 1
	// sha256HexLength is the length of a SHA-256 fingerprint in hex.
	sha256HexLength = 64
	// httpUnauthorized is a client-certificate rejection from Incus.
	httpUnauthorized = http.StatusUnauthorized
	// httpForbidden is an authorization-scriptlet denial from Incus.
	httpForbidden = http.StatusForbidden
)

// httpDoer is the subset of [http.Client] used for Incus reads.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config is the explicit, read-only connection material for an Incus identity
// reader. Every field is required except that exactly one of ServerCertPEMPath
// and ServerCertFingerprint must pin the server.
type Config struct {
	// ServerURL is the Incus HTTPS origin (scheme://host:port), with no /1.0
	// prefix. HTTP and Unix sockets are rejected.
	ServerURL string
	// ClientCertPEMPath is the path to the attestor-ro client certificate PEM.
	ClientCertPEMPath string
	// ClientKeyPEMPath is the path to the attestor-ro client private key PEM.
	ClientKeyPEMPath string
	// ServerCertPEMPath is the path to the Incus server certificate PEM used as
	// a trust anchor. Empty when ServerCertFingerprint is set.
	ServerCertPEMPath string
	// ServerCertFingerprint is the SHA-256 hex fingerprint of the Incus server
	// certificate, matching environment.certificate_fingerprint. Empty when
	// ServerCertPEMPath is set.
	ServerCertFingerprint string
	// DefaultProject is the project used when ReadInstanceByUUID is called with
	// an empty project name.
	DefaultProject attestor.ProjectName
	// RequestTimeout bounds every Incus call, including retries.
	RequestTimeout time.Duration
}

// Reader implements [attestor.InstanceReader] over two Incus GET operations.
type Reader struct {
	// base is the Incus HTTPS origin.
	base *url.URL
	// doer performs GET requests with the attestor-ro client certificate.
	doer httpDoer
	// defaultProject is used when the caller omits a project.
	defaultProject attestor.ProjectName
	// timeout is the per-call bound applied on top of the caller's context.
	timeout time.Duration
}

// NewReader validates cfg and returns a concrete [Reader].
//
// NewReader does not dial Incus. TLS material is loaded and pinned here so a
// misconfiguration fails before the first attestation read.
func NewReader(cfg Config) (*Reader, error) {
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

	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
	}

	return &Reader{
		base:           base,
		doer:           &http.Client{Transport: transport},
		defaultProject: cfg.DefaultProject,
		timeout:        cfg.RequestTimeout,
	}, nil
}

// ReadInstanceByUUID performs one filtered recursive list and maps the unique
// match to [attestor.InstanceRecord].
//
// Zero matches return [attestor.ErrInstanceNotFound]. Two or more matches
// return [attestor.ErrAmbiguousReference] with the count and never choose a
// record. An empty project uses the configured default. Transport, TLS, and
// timeout failures wrap [attestor.ErrBackendUnavailable].
func (reader *Reader) ReadInstanceByUUID(
	ctx context.Context,
	instanceUUID attestor.InstanceUUID,
	project attestor.ProjectName,
) (attestor.InstanceRecord, error) {
	if strings.TrimSpace(string(instanceUUID)) == "" {
		return attestor.InstanceRecord{}, fmt.Errorf(
			"%w: empty volatile.uuid is never a wildcard",
			attestor.ErrUnusableRecord,
		)
	}

	if strings.TrimSpace(string(project)) == "" {
		project = reader.defaultProject
	}

	query := url.Values{}
	query.Set("recursion", recursionLevel)
	query.Set("project", string(project))
	query.Set("filter", uuidFilterPrefix+string(instanceUUID))

	var instances []instancePayload
	if err := reader.getJSON(ctx, instancesPath, query, &instances); err != nil {
		return attestor.InstanceRecord{}, err
	}

	switch len(instances) {
	case 0:
		return attestor.InstanceRecord{}, attestor.ErrInstanceNotFound
	case 1:
		return mapInstance(instances[0])
	default:
		return attestor.InstanceRecord{}, fmt.Errorf(
			"%w: %d instances matched uuid %s",
			attestor.ErrAmbiguousReference,
			len(instances),
			instanceUUID,
		)
	}
}

// ReadEndpointIdentity performs GET /1.0 and returns environment.server_name
// and environment.certificate_fingerprint.
func (reader *Reader) ReadEndpointIdentity(ctx context.Context) (attestor.EndpointIdentity, error) {
	var payload serverPayload
	if err := reader.getJSON(ctx, serverPath, nil, &payload); err != nil {
		return attestor.EndpointIdentity{}, err
	}

	identity := attestor.EndpointIdentity{
		ServerName:             payload.Environment.ServerName,
		CertificateFingerprint: payload.Environment.CertificateFingerprint,
	}
	if identity.ServerName == "" && identity.CertificateFingerprint == "" {
		return attestor.EndpointIdentity{}, fmt.Errorf(
			"%w: GET /1.0 returned empty endpoint identity",
			attestor.ErrBackendUnavailable,
		)
	}

	return identity, nil
}

// getJSON issues a GET against path, decodes the Incus sync envelope into dest,
// and retries only transient transport errors.
func (reader *Reader) getJSON(ctx context.Context, path string, query url.Values, dest any) error {
	ctx, cancel := context.WithTimeout(ctx, reader.timeout)
	defer cancel()

	var last error
	for range maxAttempts {
		if err := ctx.Err(); err != nil {
			return wrapBackend(err)
		}

		last = reader.getJSONOnce(ctx, path, query, dest)
		if last == nil {
			return nil
		}
		if !isTransient(last) {
			return last
		}
	}

	return last
}

// getJSONOnce performs a single GET and decodes the Incus envelope.
func (reader *Reader) getJSONOnce(ctx context.Context, path string, query url.Values, dest any) error {
	endpoint := reader.base.JoinPath(path)
	if query != nil {
		endpoint.RawQuery = query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return wrapBackend(err)
	}

	resp, err := reader.doer.Do(req)
	if err != nil {
		return wrapBackend(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if isAuthStatus(resp.StatusCode) {
		return wrapBackend(fmt.Errorf("authorization failed: HTTP %d", resp.StatusCode))
	}
	if resp.StatusCode != http.StatusOK {
		return wrapBackend(fmt.Errorf("unexpected HTTP %d", resp.StatusCode))
	}

	limited := io.LimitReader(resp.Body, bodyOverread)
	body, err := io.ReadAll(limited)
	if err != nil {
		return wrapBackend(err)
	}
	if len(body) > maxBodyBytes {
		return wrapBackend(fmt.Errorf("response exceeded %d bytes", maxBodyBytes))
	}

	var envelope apiEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return wrapBackend(fmt.Errorf("decode Incus envelope: %w", err))
	}
	if envelope.Error != "" || envelope.ErrorCode != 0 {
		return wrapBackend(fmt.Errorf("incus error %d: %s", envelope.ErrorCode, envelope.Error))
	}
	if err := json.Unmarshal(envelope.Metadata, dest); err != nil {
		return wrapBackend(fmt.Errorf("decode Incus metadata: %w", err))
	}

	return nil
}

// apiEnvelope is the Incus synchronous REST envelope.
type apiEnvelope struct {
	// Type is "sync" for the reads this adapter issues.
	Type string `json:"type"`
	// Status is the human-readable Incus status.
	Status string `json:"status"`
	// StatusCode is the Incus status code.
	StatusCode int `json:"status_code"`
	// ErrorCode is non-zero when Incus reports a protocol error.
	ErrorCode int `json:"error_code"`
	// Error is the Incus error text.
	Error string `json:"error"`
	// Metadata is the unwrapped resource payload.
	Metadata json.RawMessage `json:"metadata"`
}

// instancePayload is the recursive instance object from GET /1.0/instances.
type instancePayload struct {
	// Name is the top-level instance name.
	Name string `json:"name"`
	// Project is the top-level project.
	Project string `json:"project"`
	// Type is the top-level type (container or virtual-machine).
	Type string `json:"type"`
	// Status is the top-level lifecycle status.
	Status string `json:"status"`
	// Location is the top-level cluster location.
	Location string `json:"location"`
	// CreatedAt is the top-level created_at timestamp.
	CreatedAt string `json:"created_at"`
	// Config holds instance config keys including volatile.uuid.
	Config map[string]string `json:"config"`
}

// serverPayload is the GET /1.0 metadata object.
type serverPayload struct {
	// Environment carries API endpoint identity.
	Environment serverEnvironment `json:"environment"`
}

// serverEnvironment is environment from GET /1.0.
type serverEnvironment struct {
	// ServerName is environment.server_name.
	ServerName string `json:"server_name"`
	// CertificateFingerprint is environment.certificate_fingerprint.
	CertificateFingerprint string `json:"certificate_fingerprint"`
}

// mapInstance copies the P5-enumerated fields into an [attestor.InstanceRecord].
func mapInstance(payload instancePayload) (attestor.InstanceRecord, error) {
	config := payload.Config
	if config == nil {
		config = map[string]string{}
	}

	instanceUUID := strings.TrimSpace(config["volatile.uuid"])
	if instanceUUID == "" {
		return attestor.InstanceRecord{}, fmt.Errorf(
			"%w: empty volatile.uuid is never a wildcard",
			attestor.ErrUnusableRecord,
		)
	}

	return attestor.InstanceRecord{
		UUID:       attestor.InstanceUUID(instanceUUID),
		Generation: attestor.GenerationUUID(strings.TrimSpace(config["volatile.uuid.generation"])),
		Project:    attestor.ProjectName(payload.Project),
		Type:       attestor.InstanceType(payload.Type),
		Status:     attestor.InstanceStatus(payload.Status),
		Location:   attestor.Location(payload.Location),
		Image:      attestor.ImageFingerprint(strings.TrimSpace(config["volatile.base_image"])),
		Name:       attestor.InstanceName(payload.Name),
		CreatedAt:  attestor.CreatedAt(payload.CreatedAt),
	}, nil
}

// validateConfig fails closed on missing TLS material, project, or timeout.
func validateConfig(cfg Config) error {
	if strings.TrimSpace(cfg.ServerURL) == "" {
		return errors.New("ServerURL is required")
	}

	parsed, err := url.Parse(strings.TrimSpace(cfg.ServerURL))
	if err != nil {
		return fmt.Errorf("parse server URL: %w", err)
	}
	if parsed.Scheme != httpsScheme || parsed.Host == "" {
		return fmt.Errorf("ServerURL must be an https origin, got %q", cfg.ServerURL)
	}

	if strings.TrimSpace(cfg.ClientCertPEMPath) == "" {
		return errors.New("ClientCertPEMPath is required")
	}
	if strings.TrimSpace(cfg.ClientKeyPEMPath) == "" {
		return errors.New("ClientKeyPEMPath is required")
	}

	pemSet := strings.TrimSpace(cfg.ServerCertPEMPath) != ""
	fingerprintSet := strings.TrimSpace(cfg.ServerCertFingerprint) != ""
	if pemSet == fingerprintSet {
		return errors.New("exactly one of ServerCertPEMPath and ServerCertFingerprint is required")
	}
	if fingerprintSet {
		if err := validateFingerprint(cfg.ServerCertFingerprint); err != nil {
			return err
		}
	}

	if strings.TrimSpace(string(cfg.DefaultProject)) == "" {
		return errors.New("DefaultProject is required")
	}
	if cfg.RequestTimeout <= 0 {
		return errors.New("RequestTimeout must be positive")
	}

	for _, path := range existingPaths(cfg) {
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("stat %s: %w", path, err)
		}
	}

	return nil
}

// existingPaths returns the PEM paths that must exist on disk.
func existingPaths(cfg Config) []string {
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

// buildTLSConfig loads the client certificate and pins the server.
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
		pool, err := loadServerPool(cfg.ServerCertPEMPath)
		if err != nil {
			return nil, err
		}
		tlsCfg.RootCAs = pool
	}

	if strings.TrimSpace(cfg.ServerCertFingerprint) != "" {
		pin := normalizeFingerprint(cfg.ServerCertFingerprint)
		if tlsCfg.RootCAs == nil {
			// The fingerprint pin is the trust root; skip system CA verification.
			tlsCfg.InsecureSkipVerify = true
		}
		tlsCfg.VerifyPeerCertificate = pinFingerprint(pin)
		tlsCfg.VerifyConnection = pinConnection(pin)
	}

	return tlsCfg, nil
}

// loadServerPool reads a server certificate PEM into a trust pool.
func loadServerPool(path string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read server certificate: %w", err)
	}

	cert, err := firstCertificate(pemBytes)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return pool, nil
}

// firstCertificate parses the first CERTIFICATE PEM block.
func firstCertificate(pemBytes []byte) (*x509.Certificate, error) {
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

		return cert, nil
	}
}

// pinFingerprint returns a VerifyPeerCertificate hook that matches leaf SHA-256.
func pinFingerprint(pin string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		return matchLeafFingerprint(pin, rawCerts)
	}
}

// pinConnection returns a VerifyConnection hook that matches leaf SHA-256 on
// every handshake, including TLS session resumption.
func pinConnection(pin string) func(tls.ConnectionState) error {
	return func(state tls.ConnectionState) error {
		rawCerts := make([][]byte, len(state.PeerCertificates))
		for i, cert := range state.PeerCertificates {
			rawCerts[i] = cert.Raw
		}

		return matchLeafFingerprint(pin, rawCerts)
	}
}

// matchLeafFingerprint compares the SHA-256 of the first presented certificate to pin.
func matchLeafFingerprint(pin string, rawCerts [][]byte) error {
	if len(rawCerts) == 0 {
		return errors.New("peer presented no certificate")
	}

	sum := sha256.Sum256(rawCerts[0])
	got := hex.EncodeToString(sum[:])
	if got != pin {
		return fmt.Errorf("server certificate fingerprint mismatch: got %s", got)
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

// wrapBackend marks transport, TLS, and timeout failures as backend unavailability.
func wrapBackend(err error) error {
	if err == nil {
		return attestor.ErrBackendUnavailable
	}
	if errors.Is(err, attestor.ErrBackendUnavailable) {
		return err
	}

	return fmt.Errorf("%w: %w", attestor.ErrBackendUnavailable, err)
}

// isAuthStatus reports authorization failures that must not be retried.
func isAuthStatus(status int) bool {
	return status == httpUnauthorized || status == httpForbidden
}

// isTransient reports genuinely transient transport errors (E3). Authorization
// failures, HTTP errors, and timeouts are not retried.
func isTransient(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}

	if isTransientErrno(err) {
		return true
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err != nil {
		return isTransient(opErr.Err)
	}

	return false
}

// isTransientErrno reports connection-reset syscalls that are worth one retry.
func isTransientErrno(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.EPIPE)
}
