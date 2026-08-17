package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/componere/incusos-spire/internal/attestor"
	"github.com/componere/incusos-spire/internal/incus/bootstrap"
	"github.com/componere/incusos-spire/internal/incus/identity"
	"github.com/componere/incusos-spire/internal/nonce"
	"github.com/componere/incusos-spire/internal/nonce/memory"
)

const (
	// envPrefix is the environment-variable prefix of every flag. Each flag
	// -some-name also reads INCUS_SPIFFE_BROKER_SOME_NAME, and the flag wins.
	envPrefix = "INCUS_SPIFFE_BROKER_"
	// defaultListenAddress serves on every interface of the broker container,
	// which in the P8 topology means its own incusbr0 address.
	defaultListenAddress = ":8443"
	// defaultNonceTTL is the bootstrap window: long enough for a guest to boot
	// and read its key, short enough that a leaked unused nonce dies quickly.
	defaultNonceTTL = 10 * time.Minute
	// defaultRequestTimeout bounds every Incus call the service makes.
	defaultRequestTimeout = 10 * time.Second
	// defaultReapInterval is the period between sweeps for expired, unredeemed
	// nonces. It is short relative to a nonce lifetime, so a secret nobody
	// redeemed leaves the guest's configuration soon after it stops working.
	defaultReapInterval = time.Minute
	// defaultReapTimeout bounds one whole sweep, which is a read and a clear per
	// expired nonce. It is deliberately larger than a single Incus call: a sweep
	// that runs out of time leaves the rest for the next tick rather than
	// abandoning anything, but a timeout that cannot fit a handful of records
	// would make no progress at all.
	defaultReapTimeout = 30 * time.Second
	// defaultReapGrace is how long past expiry a record is left alone before the
	// sweep withdraws it. It keeps the documented answers apart: an expired nonce
	// answers 409 while its record exists and 401 once it is gone, and a live run
	// that redeems seconds after expiry must see the former.
	defaultReapGrace = 2 * time.Minute
	// minMintTokenLength is the shortest operator bearer token this service
	// accepts, in characters. The token authorizes writing a bearer credential
	// into a guest's configuration, so it is held to the same floor as the
	// nonce secret it provisions: 32 characters of a random alphabet.
	minMintTokenLength = 32
	// shutdownTimeout bounds the graceful drain on SIGINT or SIGTERM.
	shutdownTimeout = 10 * time.Second
	// readHeaderTimeout bounds how long a caller may take to send headers.
	readHeaderTimeout = 5 * time.Second
	// readTimeout bounds how long a caller may take to send a whole request.
	readTimeout = 15 * time.Second
	// idleTimeout bounds a kept-alive connection between requests.
	idleTimeout = 60 * time.Second
	// maxHeaderBytes caps request headers; both request bodies are tiny.
	maxHeaderBytes = 8 << 10
)

// envLookup reads an environment variable. It is injected so option parsing is
// testable without touching the process environment.
type envLookup func(key string) (string, bool)

// options is the fully resolved configuration of the broker service. Every
// field is required except that exactly one of IncusServerCertPath and
// IncusServerFingerprint pins the Incus server.
type options struct {
	// ListenAddress is the TLS listen address, host:port. In the P8 topology
	// this is the broker container's own incusbr0 address.
	ListenAddress string
	// TLSCertPath is the path to this service's server certificate PEM. Its
	// leaf SHA-256 becomes the fingerprint every guest pins.
	TLSCertPath string
	// TLSKeyPath is the path to the matching server private key PEM.
	TLSKeyPath string
	// AdvertiseURL is the HTTPS origin a guest can reach this service on. The
	// redemption endpoint under it is written into every bootstrap payload.
	AdvertiseURL string
	// IncusURL is the Incus HTTPS origin, with no /1.0 prefix.
	IncusURL string
	// IncusServerCertPath is the Incus server certificate PEM used as a trust
	// anchor. Empty when IncusServerFingerprint is set.
	IncusServerCertPath string
	// IncusServerFingerprint is the SHA-256 hex pin of the Incus server
	// certificate. Empty when IncusServerCertPath is set.
	IncusServerFingerprint string
	// AttestorCertPath is the read-only Incus credential certificate. It
	// resolves a UUID to an instance record and nothing else.
	AttestorCertPath string
	// AttestorKeyPath is the matching read-only private key.
	AttestorKeyPath string
	// BootstrapCertPath is the write-only Incus credential certificate. It
	// writes and clears the bootstrap configuration key and nothing else.
	BootstrapCertPath string
	// BootstrapKeyPath is the matching write-only private key.
	BootstrapKeyPath string
	// Project is the default Incus project of both credentials.
	Project string
	// MintTokenPath is the file holding the operator bearer token that
	// authorizes the mint endpoint. It is required: there is no unauthenticated
	// mode, because the endpoint writes a bearer credential into a guest.
	MintTokenPath string
	// NonceTTL is the lifetime of a minted nonce.
	NonceTTL time.Duration
	// MaxNonceTTL is the longest lifetime a mint request may ask for through
	// ttl_seconds. It defaults to NonceTTL.
	MaxNonceTTL time.Duration
	// ReapInterval is the period between sweeps for expired, unredeemed nonces.
	ReapInterval time.Duration
	// ReapTimeout bounds one whole sweep, including every Incus call it makes.
	ReapTimeout time.Duration
	// ReapGrace is how long past expiry a record is left alone before it is
	// withdrawn. Zero withdraws as soon as the next sweep sees it.
	ReapGrace time.Duration
	// RequestTimeout bounds every Incus call, including retries.
	RequestTimeout time.Duration
}

// parseOptions resolves flags over environment defaults.
//
// Each flag falls back to envPrefix plus its upper-case, underscored name, so
// the same configuration works from a systemd unit and from a shell. A
// malformed duration in the environment is an error rather than a silent
// default: a service that quietly ran with a ten-minute nonce nobody asked for
// would be worse than one that refuses to start.
func parseOptions(args []string, lookupEnv envLookup) (options, error) {
	flags := flag.NewFlagSet("incus-spiffe-broker", flag.ContinueOnError)

	var opts options

	flags.StringVar(&opts.ListenAddress, "listen",
		envString(lookupEnv, "LISTEN", defaultListenAddress), "TLS listen address (host:port)")
	flags.StringVar(&opts.TLSCertPath, "tls-cert",
		envString(lookupEnv, "TLS_CERT", ""), "path to this service's server certificate PEM")
	flags.StringVar(&opts.TLSKeyPath, "tls-key",
		envString(lookupEnv, "TLS_KEY", ""), "path to this service's server private key PEM")
	flags.StringVar(&opts.AdvertiseURL, "advertise-url",
		envString(lookupEnv, "ADVERTISE_URL", ""), "HTTPS origin guests use to reach this service")
	flags.StringVar(&opts.IncusURL, "incus-url",
		envString(lookupEnv, "INCUS_URL", ""), "Incus HTTPS origin, without the /1.0 prefix")
	flags.StringVar(&opts.IncusServerCertPath, "incus-server-cert",
		envString(lookupEnv, "INCUS_SERVER_CERT", ""), "Incus server certificate PEM used as trust anchor")
	flags.StringVar(&opts.IncusServerFingerprint, "incus-server-fingerprint",
		envString(lookupEnv, "INCUS_SERVER_FINGERPRINT", ""), "SHA-256 hex pin of the Incus server certificate")
	flags.StringVar(&opts.AttestorCertPath, "attestor-cert",
		envString(lookupEnv, "ATTESTOR_CERT", ""), "read-only Incus credential certificate PEM")
	flags.StringVar(&opts.AttestorKeyPath, "attestor-key",
		envString(lookupEnv, "ATTESTOR_KEY", ""), "read-only Incus credential private key PEM")
	flags.StringVar(&opts.BootstrapCertPath, "bootstrap-cert",
		envString(lookupEnv, "BOOTSTRAP_CERT", ""), "write-only bootstrap credential certificate PEM")
	flags.StringVar(&opts.BootstrapKeyPath, "bootstrap-key",
		envString(lookupEnv, "BOOTSTRAP_KEY", ""), "write-only bootstrap credential private key PEM")
	flags.StringVar(&opts.Project, "project",
		envString(lookupEnv, "PROJECT", ""), "default Incus project of both credentials")
	flags.StringVar(&opts.MintTokenPath, "mint-token-file",
		envString(lookupEnv, "MINT_TOKEN_FILE", ""),
		"path to the file holding the operator bearer token for POST "+mintPath)

	ttl, err := envDuration(lookupEnv, "NONCE_TTL", defaultNonceTTL)
	if err != nil {
		return options{}, err
	}

	timeout, err := envDuration(lookupEnv, "REQUEST_TIMEOUT", defaultRequestTimeout)
	if err != nil {
		return options{}, err
	}

	maxTTL, err := envDuration(lookupEnv, "MAX_NONCE_TTL", 0)
	if err != nil {
		return options{}, err
	}

	reapInterval, err := envDuration(lookupEnv, "REAP_INTERVAL", defaultReapInterval)
	if err != nil {
		return options{}, err
	}

	reapTimeout, err := envDuration(lookupEnv, "REAP_TIMEOUT", defaultReapTimeout)
	if err != nil {
		return options{}, err
	}

	reapGrace, err := envDuration(lookupEnv, "REAP_GRACE", defaultReapGrace)
	if err != nil {
		return options{}, err
	}

	flags.DurationVar(&opts.NonceTTL, "nonce-ttl", ttl, "lifetime of a minted nonce")
	flags.DurationVar(&opts.MaxNonceTTL, "max-nonce-ttl", maxTTL,
		"longest lifetime a mint request may ask for; defaults to -nonce-ttl")
	flags.DurationVar(&opts.ReapInterval, "reap-interval", reapInterval,
		"period between sweeps for expired, unredeemed nonces")
	flags.DurationVar(&opts.ReapTimeout, "reap-timeout", reapTimeout,
		"bound on one whole sweep for expired, unredeemed nonces")
	flags.DurationVar(&opts.ReapGrace, "reap-grace", reapGrace,
		"how long past expiry a nonce record is kept before the sweep withdraws it")
	flags.DurationVar(&opts.RequestTimeout, "request-timeout", timeout, "bound on every Incus call")

	if parseErr := flags.Parse(args); parseErr != nil {
		return options{}, fmt.Errorf("parse flags: %w", parseErr)
	}

	if extra := flags.Args(); len(extra) > 0 {
		return options{}, fmt.Errorf("unexpected positional argument %q", extra[0])
	}

	// An unset maximum means "whatever this service already grants by default",
	// which is the only value that cannot surprise an operator who never asked
	// for a per-mint TTL at all.
	if opts.MaxNonceTTL <= 0 {
		opts.MaxNonceTTL = opts.NonceTTL
	}

	if validateErr := opts.validate(); validateErr != nil {
		return options{}, validateErr
	}

	return opts, nil
}

// validate rejects an unusable configuration, naming every fault, before
// anything is loaded or dialled.
//
// The check that the two Incus credentials are distinct files is the one rule
// that is not obvious from a single flag: P5 established that the read-only and
// write-only identities must stay separate, and a deployment that points both
// flags at one certificate has silently merged the trust boundary this whole
// design rests on.
func (o options) validate() error {
	required := []struct {
		flag  string
		value string
	}{
		{"listen", o.ListenAddress},
		{"tls-cert", o.TLSCertPath},
		{"tls-key", o.TLSKeyPath},
		{"advertise-url", o.AdvertiseURL},
		{"incus-url", o.IncusURL},
		{"attestor-cert", o.AttestorCertPath},
		{"attestor-key", o.AttestorKeyPath},
		{"bootstrap-cert", o.BootstrapCertPath},
		{"bootstrap-key", o.BootstrapKeyPath},
		{"project", o.Project},
		{"mint-token-file", o.MintTokenPath},
	}

	var faults []string

	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			faults = append(faults, "-"+field.flag+" is required")
		}
	}

	if (o.IncusServerCertPath == "") == (o.IncusServerFingerprint == "") {
		faults = append(faults, "exactly one of -incus-server-cert and -incus-server-fingerprint is required")
	}

	if o.AttestorCertPath != "" && o.AttestorCertPath == o.BootstrapCertPath {
		faults = append(faults, "-attestor-cert and -bootstrap-cert must be different credentials")
	}

	if o.NonceTTL <= 0 {
		faults = append(faults, "-nonce-ttl must be positive")
	}

	if o.RequestTimeout <= 0 {
		faults = append(faults, "-request-timeout must be positive")
	}

	if o.MaxNonceTTL < o.NonceTTL {
		faults = append(faults, "-max-nonce-ttl must not be shorter than -nonce-ttl")
	}

	if o.ReapInterval <= 0 {
		faults = append(faults, "-reap-interval must be positive")
	}

	if o.ReapTimeout <= 0 {
		faults = append(faults, "-reap-timeout must be positive")
	}

	if o.ReapGrace < 0 {
		faults = append(faults, "-reap-grace must not be negative")
	}

	if err := validateAdvertiseURL(o.AdvertiseURL); err != nil {
		faults = append(faults, err.Error())
	}

	if len(faults) > 0 {
		return fmt.Errorf("invalid configuration: %s", strings.Join(faults, "; "))
	}

	return nil
}

// redeemURL is the guest-facing redemption endpoint written into every
// bootstrap payload.
func (o options) redeemURL() nonce.BrokerURL {
	return nonce.BrokerURL(strings.TrimRight(strings.TrimSpace(o.AdvertiseURL), "/") + redeemPath)
}

// main runs the service and reports a startup or serve failure on stderr.
func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		AddSource:   false,
		Level:       slog.LevelInfo,
		ReplaceAttr: nil,
	}))

	if err := run(context.Background(), logger, os.Args[1:], os.LookupEnv); err != nil {
		logger.Error("incus-spiffe-broker stopped", fieldReason, err.Error())
		os.Exit(1)
	}
}

// run builds the object graph and serves until the process is signalled.
//
// This is the only place the graph is assembled: the operator token digest, two
// Incus adapters over two separate credentials, the nonce store, the lifecycle
// core over both, the selector core over the read adapter, the HTTP surface over
// all of them, and the reaper that withdraws what nobody redeemed.
func run(ctx context.Context, logger *slog.Logger, args []string, lookupEnv envLookup) error {
	opts, err := parseOptions(args, lookupEnv)
	if err != nil {
		return err
	}

	mintTokenDigest, err := loadMintToken(opts.MintTokenPath)
	if err != nil {
		return err
	}

	reader, err := identity.NewReader(identity.Config{
		ServerURL:             opts.IncusURL,
		ClientCertPEMPath:     opts.AttestorCertPath,
		ClientKeyPEMPath:      opts.AttestorKeyPath,
		ServerCertPEMPath:     opts.IncusServerCertPath,
		ServerCertFingerprint: opts.IncusServerFingerprint,
		DefaultProject:        attestor.ProjectName(opts.Project),
		RequestTimeout:        opts.RequestTimeout,
	})
	if err != nil {
		return fmt.Errorf("build read-only Incus adapter: %w", err)
	}

	writer, err := bootstrap.NewWriter(bootstrap.Config{
		ServerURL:             opts.IncusURL,
		ClientCertPEMPath:     opts.BootstrapCertPath,
		ClientKeyPEMPath:      opts.BootstrapKeyPath,
		ServerCertPEMPath:     opts.IncusServerCertPath,
		ServerCertFingerprint: opts.IncusServerFingerprint,
		DefaultProject:        attestor.ProjectName(opts.Project),
		RequestTimeout:        opts.RequestTimeout,
	})
	if err != nil {
		return fmt.Errorf("build bootstrap writer adapter: %w", err)
	}

	serverCert, err := tls.LoadX509KeyPair(opts.TLSCertPath, opts.TLSKeyPath)
	if err != nil {
		return fmt.Errorf("load server certificate: %w", err)
	}

	fingerprint, err := leafFingerprint(serverCert)
	if err != nil {
		return err
	}

	store := memory.New()
	minter := nonce.NewMinter(store, writer,
		nonce.WithTTL(opts.NonceTTL),
		nonce.WithBroker(opts.redeemURL(), fingerprint),
	)

	service, err := NewService(ServiceConfig{
		Reader:              reader,
		Bindings:            store,
		Minter:              minter,
		Deriver:             attestor.NewDeriver(reader),
		Logger:              logger,
		MintTokenDigest:     mintTokenDigest,
		MaxNonceTTL:         opts.MaxNonceTTL,
		CompensationTimeout: opts.RequestTimeout,
	})
	if err != nil {
		return err
	}

	reaper, err := NewReaper(ReaperConfig{
		Reader:     reader,
		Expired:    store,
		Withdrawer: minter,
		Logger:     logger,
		Interval:   opts.ReapInterval,
		Timeout:    opts.ReapTimeout,
		Grace:      opts.ReapGrace,
	})
	if err != nil {
		return err
	}

	return serve(ctx, logger, opts, service, reaper, serverCert, fingerprint)
}

// serve binds the listener, then serves TLS on it until the process is
// signalled, and drains it.
//
// The bind happens before anything is logged as ready, so the listening record
// means the port is actually held. An optimistic banner over a failed bind
// would be worse than no banner at all: the live run reads this log to decide
// that the broker is reachable.
//
// The reaper runs on the same signal context as the listener, so a drain stops
// the sweep too and no withdrawal starts against a closing process.
func serve(
	ctx context.Context,
	logger *slog.Logger,
	opts options,
	service *Service,
	reaper *Reaper,
	serverCert tls.Certificate,
	fingerprint nonce.BrokerFingerprint,
) error {
	server := &http.Server{
		Addr:    opts.ListenAddress,
		Handler: service.Handler(),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			// Both ends of this exchange are spike-issued and current, and the
			// guest pins the leaf fingerprint, so there is no legacy client to
			// accommodate.
			MinVersion: tls.VersionTLS13,
		},
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		// Without this, net/http writes transport faults such as a rejected TLS
		// handshake to the standard logger, which would put unstructured lines
		// in the middle of this service's JSON log stream.
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	var binder net.ListenConfig

	listener, err := binder.Listen(ctx, "tcp", opts.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", opts.ListenAddress, err)
	}

	signalled, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.InfoContext(signalled, "incus-spiffe-broker listening",
		"listen_address", listener.Addr().String(),
		"redeem_url", string(opts.redeemURL()),
		"tls_fingerprint", string(fingerprint),
		"incus_url", opts.IncusURL,
		fieldProject, opts.Project,
		"nonce_ttl", opts.NonceTTL.String(),
		"max_nonce_ttl", opts.MaxNonceTTL.String(),
		"reap_interval", opts.ReapInterval.String(),
		"reap_timeout", opts.ReapTimeout.String(),
		"reap_grace", opts.ReapGrace.String(),
		"request_timeout", opts.RequestTimeout.String(),
	)

	go reaper.Run(signalled)

	failures := make(chan error, 1)

	go func() {
		failures <- server.ServeTLS(listener, "", "")
	}()

	select {
	case err := <-failures:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}

		return fmt.Errorf("serve TLS on %s: %w", opts.ListenAddress, err)

	case <-signalled.Done():
		logger.InfoContext(ctx, "incus-spiffe-broker draining")

		drain, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer cancel()

		if err := server.Shutdown(drain); err != nil {
			return fmt.Errorf("drain listener: %w", err)
		}

		return nil
	}
}

// leafFingerprint returns the SHA-256 of the server certificate's leaf, which is
// the value a guest pins.
//
// It is derived from the loaded certificate rather than configured separately:
// a fingerprint an operator types by hand can drift from the certificate in
// use, and every guest that pins the stale value would fail to bootstrap.
func leafFingerprint(cert tls.Certificate) (nonce.BrokerFingerprint, error) {
	if len(cert.Certificate) == 0 {
		return "", errors.New("server certificate contains no leaf")
	}

	digest := sha256.Sum256(cert.Certificate[0])

	return nonce.BrokerFingerprint(hex.EncodeToString(digest[:])), nil
}

// loadMintToken reads the operator bearer token and returns its SHA-256 digest.
//
// Only the digest travels into the service. The token itself is needed exactly
// once, at startup, and a process that keeps a credential it will never present
// has only created another place for it to leak from.
//
// A missing file and a short token are both startup failures. There is no
// "authentication optional" mode: the endpoint this token guards writes a
// bearer credential into a guest's configuration and spends both privileged
// Incus credentials to do it, so a deployment that cannot produce a token is a
// deployment that must not listen. The length floor is what makes the token
// worth comparing at all; a short one would be guessable at a rate no
// constant-time comparison can help with. Neither the token nor any part of it
// appears in the error.
func loadMintToken(path string) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte

	raw, err := os.ReadFile(path)
	if err != nil {
		return digest, fmt.Errorf("read operator mint token: %w", err)
	}

	token := strings.TrimSpace(string(raw))
	if len(token) < minMintTokenLength {
		return digest, fmt.Errorf(
			"operator mint token in %s is %d characters; -mint-token-file requires at least %d",
			path, len(token), minMintTokenLength,
		)
	}

	return sha256.Sum256([]byte(token)), nil
}

// envString returns the environment default for a flag, or fallback.
func envString(lookupEnv envLookup, name string, fallback string) string {
	if value, found := lookupEnv(envPrefix + name); found && value != "" {
		return value
	}

	return fallback
}

// envDuration returns the environment default for a duration flag, or fallback.
// A value that is present but unparseable is an error.
func envDuration(lookupEnv envLookup, name string, fallback time.Duration) (time.Duration, error) {
	raw, found := lookupEnv(envPrefix + name)
	if !found || raw == "" {
		return fallback, nil
	}

	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("parse %s%s: %w", envPrefix, name, err)
	}

	return value, nil
}

// validateAdvertiseURL enforces an HTTPS origin without a path: the guest sends
// a nonce secret to this URL, so plain HTTP is never acceptable, and the
// redemption path is appended by this service rather than configured.
func validateAdvertiseURL(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("-advertise-url is not a URL: %w", err)
	}

	if parsed.Scheme != "https" {
		return errors.New("-advertise-url must use https")
	}

	if parsed.Host == "" {
		return errors.New("-advertise-url must include a host")
	}

	if strings.Trim(parsed.Path, "/") != "" {
		return errors.New("-advertise-url must not include a path")
	}

	return nil
}
