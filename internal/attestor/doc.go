// Package attestor is the pure selector-derivation core for Incus workload
// attestation.
//
// The package performs no I/O. It holds the consumer-owned [InstanceReader]
// port (A1) and applies the frozen P6 trust rules to an [InstanceRecord] read
// through that port. Adapters in other packages implement the port; this
// package never imports an Incus client, [net/http], or a clock.
//
// Callers construct a [Deriver] with [NewDeriver] and invoke [Deriver.Derive]
// with a broker-submitted [Reference]. Successful derivation always returns
// the six frozen selectors in a deterministic order. Failures are wrapped so
// [errors.Is] matches the sentinel that names the trust-rule violation.
package attestor
