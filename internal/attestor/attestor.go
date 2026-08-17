package attestor

import (
	"context"
	"strings"
)

// InstanceUUID is the canonical textual form of an Incus instance
// volatile.uuid value. Empty is never a wildcard.
type InstanceUUID string

// GenerationUUID is the canonical textual form of an Incus instance
// volatile.uuid.generation value.
type GenerationUUID string

// ProjectName is an Incus project name. Empty on a [Reference] means the
// adapter's configured project.
type ProjectName string

// InstanceName is the Incus instance record name. It is informational only.
type InstanceName string

// ImageFingerprint is an Incus volatile.base_image fingerprint. It is
// provenance only and is not cross-checked by Incus against instance type.
type ImageFingerprint string

// Location is the Incus instance cluster location. On a non-clustered host
// this is "none". It is carried for a future cluster and is never a selector.
type Location string

// CreatedAt is the Incus instance created_at timestamp in RFC 3339 text.
// It is corroboration only and is never a selector.
type CreatedAt string

// InstanceType is the Incus instance record type.
type InstanceType string

const (
	// InstanceTypeContainer is an Incus container.
	InstanceTypeContainer InstanceType = "container"
	// InstanceTypeVirtualMachine is an Incus virtual machine.
	InstanceTypeVirtualMachine InstanceType = "virtual-machine"
)

// InstanceStatus is the Incus instance lifecycle status. It is a policy input
// and is never emitted as a selector.
type InstanceStatus string

const (
	// InstanceStatusRunning is the only status that attests under the default policy.
	InstanceStatusRunning InstanceStatus = "Running"
	// InstanceStatusStopped is a live Incus status that the default policy rejects.
	InstanceStatusStopped InstanceStatus = "Stopped"
)

// Reference is the broker-submitted workload claim. Only InstanceUUID selects
// an instance; Project, Generation, and Server are equality checks that can
// only narrow the outcome. The type carries claims, never facts.
type Reference struct {
	// InstanceUUID is the sole required identity anchor. It is checked against
	// the instance config key volatile.uuid.
	InstanceUUID InstanceUUID
	// Project scopes the lookup. Empty means the adapter's configured project.
	// When set, it is checked against the instance record's top-level project.
	Project ProjectName
	// Generation is an optional expectation. When set, it MUST equal the live
	// volatile.uuid.generation or attestation fails. This is how a caller pins
	// "the instance has not been rolled back since I minted this credential".
	Generation GenerationUUID
	// Server is an optional expectation. When set, it MUST equal the plugin's
	// configured endpoint identity or attestation fails. It never selects which
	// Incus to talk to.
	Server string
}

// InstanceRecord is the value type returned by [InstanceReader.ReadInstanceByUUID].
// It carries exactly the P5-enumerated reads, one field per authoritative source.
type InstanceRecord struct {
	// UUID is config volatile.uuid.
	UUID InstanceUUID
	// Generation is config volatile.uuid.generation.
	Generation GenerationUUID
	// Project is the instance record top-level project.
	Project ProjectName
	// Type is the instance record top-level type.
	Type InstanceType
	// Status is the instance record top-level status. It is a policy input, not a selector.
	Status InstanceStatus
	// Location is the instance record top-level location. It is carried for a
	// future cluster and is never a selector.
	Location Location
	// Image is config volatile.base_image. It is provenance only.
	Image ImageFingerprint
	// Name is the instance record top-level name. It is informational only and
	// must never be used alone in a registration entry.
	Name InstanceName
	// CreatedAt is the instance record created_at. It is corroboration only.
	CreatedAt CreatedAt
}

// EndpointIdentity is the Incus API endpoint identity from GET /1.0. It is used
// only to check a [Reference] Server expectation.
type EndpointIdentity struct {
	// ServerName is environment.server_name.
	ServerName string
	// CertificateFingerprint is environment.certificate_fingerprint.
	CertificateFingerprint string
}

// Selector is a SPIRE selector in the frozen P6 form `incus:<key>:<value>`.
// SPIRE derives the selector type from the plugin name, so an external plugin
// returns only the value part; this type keeps the type prefix for
// documentation and evidence.
type Selector string

// TypeAndValue splits a selector into its SPIRE type and value.
//
// For Selector("incus:uuid:<v>") it returns ("incus", "uuid:<v>"). SPIRE
// derives the selector type from the plugin name, so an external plugin
// returns only the value part; the frozen P6 form keeps the type prefix for
// documentation and evidence.
func (s Selector) TypeAndValue() (string, string) {
	typeName, value, found := strings.Cut(string(s), ":")
	if !found {
		return string(s), ""
	}

	return typeName, value
}

// InstanceReader is the consumer-owned port for Incus identity reads.
//
// Adapters implement it; this package never performs I/O. The adapter MUST NOT
// choose among multiple matches: more than one instance for a UUID is
// [ErrAmbiguousReference] and no record. Zero matches is [ErrInstanceNotFound],
// distinct from a transport error, so the plugin can answer "no selectors"
// instead of "backend broken".
//
// A backend failure carries its retryability with it: [ErrBackendUnavailable]
// for a transient transport fault, [ErrBackendUnauthorized] for a credential
// refusal, and [ErrBackendPermanent] for a protocol or configuration fault.
// The adapter classifies once, and every layer above reads the classification
// instead of guessing from a status code.
type InstanceReader interface {
	// ReadInstanceByUUID returns the unique instance whose volatile.uuid matches
	// uuid. An empty project means the adapter's configured project. The adapter
	// returns the whole record in one call and must not issue a read-per-field.
	ReadInstanceByUUID(ctx context.Context, uuid InstanceUUID, project ProjectName) (InstanceRecord, error)
	// ReadEndpointIdentity returns the server name and API certificate
	// fingerprint from GET /1.0. The core calls it only when [Reference.Server]
	// is non-empty.
	ReadEndpointIdentity(ctx context.Context) (EndpointIdentity, error)
}

// sentinelError is a comparable sentinel used with [errors.Is].
type sentinelError string

// Error returns the sentinel's stable message.
func (e sentinelError) Error() string {
	return string(e)
}

const (
	// ErrInvalidReference is returned when InstanceUUID is empty or not a
	// canonical UUID. Empty is never treated as a wildcard.
	ErrInvalidReference sentinelError = "attestor: invalid instance reference"
	// ErrInstanceNotFound is returned by [InstanceReader] when no instance
	// matches the UUID. [Deriver.Derive] propagates it unchanged.
	ErrInstanceNotFound sentinelError = "attestor: instance not found"
	// ErrAmbiguousReference is returned by [InstanceReader] when more than one
	// instance matches the UUID. [Deriver.Derive] never selects one of several
	// records. Wrapped messages MUST include the match count.
	ErrAmbiguousReference sentinelError = "attestor: ambiguous instance reference"
	// ErrUnusableRecord is returned when the instance record cannot be attested:
	// empty or mismatched volatile.uuid, a disallowed status, or a project
	// expectation that does not match the live record.
	ErrUnusableRecord sentinelError = "attestor: unusable instance record"
	// ErrGenerationMismatch is returned when Reference.Generation is set and
	// does not equal the live volatile.uuid.generation. Restore always produces
	// a new generation, so a mismatch means the instance was rolled back after
	// the credential was minted.
	ErrGenerationMismatch sentinelError = "attestor: generation mismatch"
	// ErrEndpointMismatch is returned when Reference.Server is set and equals
	// neither [EndpointIdentity.ServerName] nor
	// [EndpointIdentity.CertificateFingerprint].
	ErrEndpointMismatch sentinelError = "attestor: endpoint mismatch"
	// ErrBackendUnavailable is returned when the Incus API could not be reached
	// for a genuinely transient reason: a refused or reset connection, a
	// black-holed endpoint, or the bounded request timeout expiring.
	//
	// Retry semantics: RETRYABLE. The adapter retries it within its own bounded
	// budget, and an outer caller may retry it again. It is the only backend
	// sentinel the plugin reports as gRPC Unavailable.
	ErrBackendUnavailable sentinelError = "attestor: backend unavailable"
	// ErrBackendUnauthorized is returned when the Incus API refused the
	// attestor's credential, that is HTTP 401 or 403.
	//
	// Retry semantics: NEVER RETRY. The denial is a property of the deployed
	// client certificate and of the server-side authorization policy, so every
	// repeat of the same read earns the same denial.
	ErrBackendUnauthorized sentinelError = "attestor: backend authorization failed"
	// ErrBackendPermanent is returned when the Incus API was reached but the
	// exchange cannot succeed without an operator change: a malformed or
	// oversized body, an Incus error envelope, an unexpected HTTP status, an
	// empty endpoint identity, or a TLS or configuration rejection such as a
	// server certificate that fails the configured pin.
	//
	// Retry semantics: NEVER RETRY. Retrying a configuration or protocol fault
	// only multiplies the failure.
	ErrBackendPermanent sentinelError = "attestor: backend permanent failure"
)
