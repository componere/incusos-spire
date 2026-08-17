package attestor

import (
	"context"
	"errors"
	"fmt"
)

const (
	// selectorType is the SPIRE selector type, equal to the plugin name.
	selectorType = "incus"
	// uuidTextLength is the RFC 4122 textual UUID length, including dashes.
	uuidTextLength = 36
	uuidDashIndex1 = 8
	uuidDashIndex2 = 13
	uuidDashIndex3 = 18
	uuidDashIndex4 = 23
)

// statusSet is the set of instance statuses that may attest.
type statusSet map[InstanceStatus]struct{}

// Option configures a [Deriver].
type Option func(*Deriver)

// WithAllowedStatuses replaces the default allowed-status policy. The default
// allows only [InstanceStatusRunning]. An empty list fails closed.
func WithAllowedStatuses(statuses ...InstanceStatus) Option {
	return func(deriver *Deriver) {
		deriver.allowedStatuses = newStatusSet(statuses...)
	}
}

// newStatusSet builds an allowed-status set. An empty list fails closed.
func newStatusSet(statuses ...InstanceStatus) statusSet {
	allowed := make(statusSet, len(statuses))
	for _, status := range statuses {
		allowed[status] = struct{}{}
	}

	return allowed
}

// Deriver applies the unexported P6 trust rules and emits the frozen selector set.
type Deriver struct {
	// reader is the Incus identity port. It is required and never nil after
	// [NewDeriver] returns.
	reader InstanceReader
	// allowedStatuses is the attest-time status policy. The default contains
	// only [InstanceStatusRunning].
	allowedStatuses statusSet
}

// NewDeriver returns a [Deriver] that reads instance state through reader.
// The default allowed-status policy attests only [InstanceStatusRunning].
func NewDeriver(reader InstanceReader, opts ...Option) *Deriver {
	if reader == nil {
		panic("attestor: NewDeriver requires a non-nil InstanceReader")
	}

	deriver := &Deriver{
		reader:          reader,
		allowedStatuses: newStatusSet(InstanceStatusRunning),
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}

		opt(deriver)
	}

	return deriver
}

// Derive reads the instance identified by ref and returns the six frozen
// selectors in deterministic order:
//
//	incus:uuid:<volatile.uuid>
//	incus:generation:<volatile.uuid.generation>
//	incus:project:<project>
//	incus:type:<type>
//	incus:name:<name>
//	incus:image:<volatile.base_image>
//
// incus:name is informational only and must never be used alone in a
// registration entry. incus:image is provenance only; Incus does not
// cross-check it against instance type.
//
// The following selectors are never emitted: incus:status, incus:location,
// incus:server, incus:cloudinit-id, incus:created-at.
func (d *Deriver) Derive(ctx context.Context, ref Reference) ([]Selector, error) {
	if err := validateReference(ref); err != nil {
		return nil, err
	}

	record, err := d.readInstance(ctx, ref)
	if err != nil {
		return nil, err
	}

	if err := checkRecord(ref, record); err != nil {
		return nil, err
	}

	if err := d.checkEndpoint(ctx, ref); err != nil {
		return nil, err
	}

	if err := d.checkStatus(record); err != nil {
		return nil, err
	}

	return emitSelectors(record), nil
}

// validateReference enforces that InstanceUUID is a canonical UUID. Empty is
// never a wildcard.
func validateReference(ref Reference) error {
	if !isCanonicalUUID(string(ref.InstanceUUID)) {
		return fmt.Errorf(
			"attestor: instance uuid %q is empty or not canonical: %w",
			ref.InstanceUUID,
			ErrInvalidReference,
		)
	}

	return nil
}

// readInstance calls the port and maps reader errors onto the failure taxonomy.
func (d *Deriver) readInstance(ctx context.Context, ref Reference) (InstanceRecord, error) {
	record, err := d.reader.ReadInstanceByUUID(ctx, ref.InstanceUUID, ref.Project)
	if err == nil {
		return record, nil
	}

	if errors.Is(err, ErrInstanceNotFound) || errors.Is(err, ErrAmbiguousReference) {
		return InstanceRecord{}, err
	}

	return InstanceRecord{}, wrapBackend("instance lookup", err)
}

// checkRecord enforces record UUID presence and equality, optional generation
// equality, and optional project equality. It never picks among records; the
// reader has already failed closed on ambiguity.
func checkRecord(ref Reference, record InstanceRecord) error {
	if record.UUID == "" || record.UUID != ref.InstanceUUID {
		return fmt.Errorf(
			"attestor: requested uuid %q does not match record uuid %q: %w",
			ref.InstanceUUID,
			record.UUID,
			ErrUnusableRecord,
		)
	}

	if ref.Generation != "" && ref.Generation != record.Generation {
		return fmt.Errorf(
			"attestor: expected generation %q does not match live generation %q: %w",
			ref.Generation,
			record.Generation,
			ErrGenerationMismatch,
		)
	}

	if ref.Project != "" && ref.Project != record.Project {
		return fmt.Errorf(
			"attestor: expected project %q does not match live project %q: %w",
			ref.Project,
			record.Project,
			ErrUnusableRecord,
		)
	}

	return nil
}

// checkEndpoint enforces the optional server expectation. It calls
// [InstanceReader.ReadEndpointIdentity] only when ref.Server is non-empty.
func (d *Deriver) checkEndpoint(ctx context.Context, ref Reference) error {
	if ref.Server == "" {
		return nil
	}

	identity, err := d.reader.ReadEndpointIdentity(ctx)
	if err != nil {
		if errors.Is(err, ErrInstanceNotFound) || errors.Is(err, ErrAmbiguousReference) {
			return err
		}

		return wrapBackend("endpoint identity lookup", err)
	}

	if ref.Server == identity.ServerName || ref.Server == identity.CertificateFingerprint {
		return nil
	}

	return fmt.Errorf(
		"attestor: server %q matches neither endpoint name %q nor fingerprint %q: %w",
		ref.Server,
		identity.ServerName,
		identity.CertificateFingerprint,
		ErrEndpointMismatch,
	)
}

// checkStatus rejects records whose status is not in the allowed set.
func (d *Deriver) checkStatus(record InstanceRecord) error {
	if _, ok := d.allowedStatuses[record.Status]; ok {
		return nil
	}

	return fmt.Errorf(
		"attestor: instance %s status %q is not allowed: %w",
		record.UUID,
		record.Status,
		ErrUnusableRecord,
	)
}

// emitSelectors returns the six frozen selectors in deterministic order.
func emitSelectors(record InstanceRecord) []Selector {
	return []Selector{
		selector("uuid", string(record.UUID)),
		selector("generation", string(record.Generation)),
		selector("project", string(record.Project)),
		selector("type", string(record.Type)),
		selector("name", string(record.Name)),
		selector("image", string(record.Image)),
	}
}

// selector builds a frozen P6 selector `incus:key:value`.
func selector(key, value string) Selector {
	return Selector(selectorType + ":" + key + ":" + value)
}

// wrapBackend marks a reader transport failure as [ErrBackendUnavailable]
// while preserving the original error for [errors.Is].
func wrapBackend(op string, err error) error {
	return fmt.Errorf("attestor: %s failed: %w: %w", op, ErrBackendUnavailable, err)
}

// isCanonicalUUID reports whether value is a lowercase RFC 4122 textual UUID.
func isCanonicalUUID(value string) bool {
	if len(value) != uuidTextLength {
		return false
	}

	for i := range uuidTextLength {
		if isUUIDDashIndex(i) {
			if value[i] != '-' {
				return false
			}

			continue
		}

		if !isLowerHex(value[i]) {
			return false
		}
	}

	return true
}

// isUUIDDashIndex reports whether i is one of the four dash positions in a
// textual UUID.
func isUUIDDashIndex(i int) bool {
	switch i {
	case uuidDashIndex1, uuidDashIndex2, uuidDashIndex3, uuidDashIndex4:
		return true
	default:
		return false
	}
}

// isLowerHex reports whether b is a lowercase hexadecimal digit.
func isLowerHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')
}
