# P7 Broker API operator harness

**This directory is disposable spike tooling.** Appendix C of `SPIKE_PLAN.md`
classifies everything under `spike/` as never merged as product code: it is
throwaway configs and operator scripts, deletable without loss, because the
evidence it produces lives in the journal. The durable counterpart is
`internal/broker`, the only package allowed to touch the experimental Broker API
client surface. Do not import, wrap, or promote anything here.

`drive-broker.sh` drives the SPIRE 1.15.2 agent Broker endpoint
(`spiffe.broker.API`) over its Unix domain socket with `grpcurl` and prints a
verdict per case. It exits `0` when every case matches its expected outcome and
`1` otherwise, so it can gate the P7 acceptance run and be replayed after any
SPIRE or go-spiffe bump.

## Before you run it

1. A SPIRE agent with the `experimental.broker` block configured, `socket_path`
   set, and `brokers[]` containing the broker SPIFFE ID whose SVID you are about
   to use. See `BROKER_BRIEF.md` section 3 for the exact block.
2. The broker's own X.509-SVID, obtained from the agent's Workload API, written
   out as a PEM certificate chain and an unencrypted PEM private key. The
   endpoint is mutual TLS even over the Unix socket, and the certificate's
   SPIFFE ID must exactly equal a configured `brokers[].id`.
3. `grpcurl` on the host. `protoc`, `go`, and `jq` are needed only the first
   time, to build the descriptor set.

## Running it

```sh
BROKER_SOCKET=/run/spire/broker-sockets/broker.sock \
BROKER_SVID_CERT_PEM=/run/incus-broker/svid.pem \
BROKER_SVID_KEY_PEM=/run/incus-broker/svid-key.pem \
INSTANCE_UUID=e9e6a2a0-d695-42d3-8e8c-92d290bfc7da \
./drive-broker.sh
```

Every knob is an environment variable with a working default, so the script never
needs editing:

| Variable | Default | Purpose |
| --- | --- | --- |
| `GRPCURL_BIN` | `grpcurl` | `grpcurl` binary or absolute path |
| `PROTOC_BIN` | `protoc` | `protoc` binary, used only to build the protoset |
| `BROKER_SOCKET` | `/run/spire/broker-sockets/broker.sock` | agent `experimental.broker.socket_path` |
| `BROKER_SVID_CERT_PEM` | `/run/incus-broker/svid.pem` | broker SVID certificate chain, PEM |
| `BROKER_SVID_KEY_PEM` | `/run/incus-broker/svid-key.pem` | broker SVID private key, PEM, unencrypted |
| `PROTOSET` | `/tmp/incus-broker.protoset` | descriptor set; built on demand when absent |
| `REPO_ROOT` | the repository containing this script | where `proto/` is found |
| `GO_SPIFFE_VERSION` | `v2.8.1` | go-spiffe version supplying the Broker proto |
| `REFERENCE_TYPE_URL` | the frozen P6 URL | `Any.type_url` for the positive case |
| `INSTANCE_UUID` | the P6 spike guest UUID | `config.volatile.uuid` of the target instance |
| `INSTANCE_PROJECT` | `spike-spiffe` | Incus project of the target instance |
| `GENERATION_UUID` | the P6 spike generation | `config.volatile.uuid.generation` |
| `SERVER_FINGERPRINT` | the P6 spike endpoint fingerprint | Incus endpoint identity |
| `WRONG_TYPE_URL` | `type.googleapis.com/spiffe.broker.WorkloadPIDReference` | deliberately disallowed type for case 3 |
| `MAX_TIME` | `10` | seconds each streaming call is allowed to stay open |
| `PROBE_REFLECTION` | `0` | set to `1` to add the header-gated reflection probe |

The descriptor set is built from the pinned go-spiffe Broker proto plus
`proto/componere/incus/v1alpha1/reference.proto` with `--include_imports`. It is
preferred over reflection because reflection on the agent cannot describe the
vendor `IncusInstanceReference` message that the `Any` carries.

## What each case proves

All three cases invoke the same method, `spiffe.broker.API/SubscribeToX509SVID`,
with the reference nested exactly as the API requires: the `Any` inside a
`WorkloadReference` inside `SubscribeToX509SVIDRequest`.

| Case | Change from the positive call | Proves | Expected result |
| --- | --- | --- | --- |
| `positive` | none | an allowlisted `type_url` with the mandatory header reaches the `incus` attestor and returns an SVID | an `X509SVID` with a `spiffeId` is streamed |
| `missing-header` | `-rpc-header` omitted | the security header is enforced ahead of everything else | `code = InvalidArgument`, `desc = security header missing from request` |
| `wrong-type` | `Any.type_url` outside `allowed_reference_types` | reference-type authorization happens before attestation, so no plugin runs | `code = PermissionDenied`, `desc = broker "<id>" is not allowed to use reference type "<url>"` |

Two result shapes are easy to misread:

- `SubscribeToX509SVID` is server-streaming and stays subscribed for updates, so
  the positive case ends with `code = DeadlineExceeded` once `MAX_TIME` elapses.
  The SVID has already printed by then; the verdict looks for the delivered
  `spiffeId`, not for a zero exit code.
- A `type_url` that the allowlist permits but no attestor handles is
  `Unimplemented`, `no workload attestor handled reference`, not
  `PermissionDenied`. Seeing that from case 1 means the broker gate passed and
  the `incus` plugin did not answer.

## Not covered here: the unauthorized broker ID

An otherwise valid SVID whose SPIFFE ID is absent from `brokers[]` is rejected
during the TLS handshake, before any RPC reaches the service, so the server emits
no gRPC status at all. To exercise that case, point
`BROKER_SVID_CERT_PEM`/`BROKER_SVID_KEY_PEM` at material for an unconfigured
SPIFFE ID and expect a transport-level handshake failure plus a TLS rejection in
the agent log. The exact `grpcurl` text is client-version dependent, so capture
both sides; the acceptance criterion is the failed handshake and the absence of
an attestor call, not a status code.

## Reflection caveat

Reflection is enabled in SPIRE 1.15.2, contrary to what one might assume of an
experimental endpoint, but it is restricted twice over:

- It works only over the Unix socket. A reflection call over TCP returns
  `PermissionDenied`, `server reflection is only available over Unix sockets`.
- The security-header middleware covers reflection too, so `grpcurl` needs
  `-rpc-header 'broker.spiffe.io: true'` even to list services. Without it,
  `grpcurl ... list` returns `InvalidArgument`.

`PROBE_REFLECTION=1` runs that probe as an extra, non-fatal step. The client
certificate flags are still required: mutual TLS applies to the whole gRPC
server, reflection included. The SPIRE agent docs show a reflection command
without `-cert`/`-key`; that command cannot work against this endpoint.
