// Package broker is the sole adapter over the experimental SPIFFE Broker API
// client surface.
//
// # Isolation contract
//
// This package is the only place in the repository permitted to import
// [github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker] or the go-spiffe
// pieces used to obtain the broker's own X.509-SVID. Nothing it exports leaks
// those types: callers pass a [google.golang.org/protobuf/types/known/anypb.Any]
// reference and receive [X509SVID], a plain value type owned here.
//
// The reason is spike risk register R3: the Broker block is experimental in
// SPIRE 1.15.2 and upstream warns that breaking changes may land before
// stabilization, while the SPIFFE standard labels the API "Incubating". Keeping
// the generated experimental package behind this one adapter means an upstream
// break is a single-package edit with a fixed blast radius (SPIKE_PLAN.md
// Appendix C), not a repository-wide migration. Pin SPIRE and go-spiffe, and
// rerun the P7 acceptance cases on any bump.
//
// # Endpoint facts this adapter encodes
//
// The endpoint is always mutual TLS, including over its Unix socket, and the
// broker must present an X.509-SVID whose SPIFFE ID appears in the agent's
// configured brokers[] list. Every call must carry exactly one metadata value
// "broker.spiffe.io: true"; the connection's interceptors attach it, because
// SPIRE answers InvalidArgument when it is missing. The workload reference is
// nested twice: an Any inside WorkloadReference inside the method request.
package broker
