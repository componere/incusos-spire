# SPIRE 1.15.2 Broker API and external `AttestReference` brief

**Implementation target:** SPIRE `v1.15.2` only. The exact dependency pins in that tag are `github.com/spiffe/go-spiffe/v2 v2.8.1` and `github.com/spiffe/spire-plugin-sdk v1.4.4-0.20260617144146-5dcde407c4d1`, not a plugin-SDK tag named `v1.15.2` ([`spiffe/spire@v1.15.2/go.mod`, lines 80–82](https://github.com/spiffe/spire/blob/v1.15.2/go.mod#L80-L82)). The SPIFFE standard was read at commit `dc4e9d9b4eff8aa181a54cd330ff9f877186060e`; the SPIRE and dependency source pinned above controls where the standard and implementation differ.

## Decisions for P7

- The public service is `spiffe.broker.API`. For the X.509 positive case, invoke `spiffe.broker.API/SubscribeToX509SVID`.
- SPIRE 1.15.2 **does enable reflection**, but only over a Unix-domain socket. Reflection requests also require `broker.spiffe.io: true`.
- The endpoint always uses mutual TLS, including over its Unix socket. The broker must present an X.509-SVID whose SPIFFE ID exactly equals a configured `brokers[].id`.
- Configure the external plugin as `WorkloadAttestor "incus"`. The plugin returns values such as `uuid:<uuid>`, not `incus:uuid:<uuid>`; SPIRE supplies the `incus` selector type from the plugin name.
- The Incus reference URL must match exactly in two places: the broker allowlist and the plugin's `google.protobuf.Any.type_url`: `type.googleapis.com/componere.incus.v1alpha1.IncusInstanceReference`.
- A reference type excluded by the configured broker allowlist fails with gRPC `PermissionDenied`, not `InvalidArgument`.
- A broker SPIFFE ID excluded from `brokers[]` is rejected during the TLS handshake. No Broker API RPC runs and therefore the server emits no gRPC status for that case.

## 1. Public Broker API service and messages

SPIRE registers the `API` service from `github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker`. The exact wire service and four methods in the `v2.8.1` proto are:

```protobuf
package spiffe.broker;

service API {
  rpc SubscribeToX509SVID(SubscribeToX509SVIDRequest)
      returns (stream SubscribeToX509SVIDResponse);
  rpc SubscribeToX509Bundles(SubscribeToX509BundlesRequest)
      returns (stream SubscribeToX509BundlesResponse);
  rpc FetchJWTSVID(FetchJWTSVIDRequest)
      returns (FetchJWTSVIDResponse);
  rpc SubscribeToJWTBundles(SubscribeToJWTBundlesRequest)
      returns (stream SubscribeToJWTBundlesResponse);
}
```

> Source: [`spiffe/go-spiffe@v2.8.1/exp/proto/spiffe/broker/api.proto`, lines 8–35](https://github.com/spiffe/go-spiffe/blob/v2.8.1/exp/proto/spiffe/broker/api.proto#L8-L35): “`service API`”, “`rpc SubscribeToX509SVID`”, “`rpc SubscribeToX509Bundles`”, “`rpc FetchJWTSVID`”, and “`rpc SubscribeToJWTBundles`”. SPIRE registers that generated service with `broker.RegisterAPIServer` ([`spiffe/spire@v1.15.2/pkg/agent/broker/api/service.go`, lines 31–34](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/broker/api/service.go#L31-L34)).

All requests nest the opaque reference twice: the method request has a `spiffe.broker.WorkloadReference reference`, and that message has `google.protobuf.Any reference`:

```protobuf
message WorkloadReference {
  google.protobuf.Any reference = 1; // required
}

message SubscribeToX509SVIDRequest {
  WorkloadReference reference = 1; // required
}

message SubscribeToX509BundlesRequest {
  WorkloadReference reference = 1; // required
}

message FetchJWTSVIDRequest {
  WorkloadReference reference = 1; // required
  repeated string audience = 2;    // required
  string spiffe_id = 3;            // optional
}

message SubscribeToJWTBundlesRequest {
  WorkloadReference reference = 1; // required
}
```

> Source: [`api.proto`, lines 38–44](https://github.com/spiffe/go-spiffe/blob/v2.8.1/exp/proto/spiffe/broker/api.proto#L38-L44), [109–111](https://github.com/spiffe/go-spiffe/blob/v2.8.1/exp/proto/spiffe/broker/api.proto#L109-L111), [156–170](https://github.com/spiffe/go-spiffe/blob/v2.8.1/exp/proto/spiffe/broker/api.proto#L156-L170), [174–189](https://github.com/spiffe/go-spiffe/blob/v2.8.1/exp/proto/spiffe/broker/api.proto#L174-L189), and [208–217](https://github.com/spiffe/go-spiffe/blob/v2.8.1/exp/proto/spiffe/broker/api.proto#L208-L217). The standard confirms that `WorkloadReference.reference` is the extension point using `google.protobuf.Any` ([`spiffe/spiffe@dc4e9d9/standards/SPIFFE_Broker_API.md`, lines 215–219](https://github.com/spiffe/spiffe/blob/dc4e9d9b4eff8aa181a54cd330ff9f877186060e/standards/SPIFFE_Broker_API.md#L215-L219)).

The response shapes are:

```protobuf
message SubscribeToX509SVIDResponse {
  repeated X509SVID svids = 1;
  repeated bytes crl = 2;
  map<string, bytes> federated_bundles = 3;
}
message X509SVID {
  string spiffe_id = 1;
  bytes x509_svid = 2;      // DER chain, leaf first
  bytes x509_svid_key = 3;  // unencrypted PKCS#8 DER
  bytes bundle = 4;         // DER bundle
  string hint = 5;
}
message SubscribeToX509BundlesResponse {
  repeated bytes crl = 1;
  map<string, bytes> bundles = 2;
}
message FetchJWTSVIDResponse { repeated JWTSVID svids = 1; }
message JWTSVID {
  string spiffe_id = 1;
  string svid = 2;
  string hint = 3;
}
message SubscribeToJWTBundlesResponse {
  map<string, bytes> bundles = 1;
}
```

> Source: [`api.proto`, lines 117–153](https://github.com/spiffe/go-spiffe/blob/v2.8.1/exp/proto/spiffe/broker/api.proto#L117-L153), [163–170](https://github.com/spiffe/go-spiffe/blob/v2.8.1/exp/proto/spiffe/broker/api.proto#L163-L170), [187–203](https://github.com/spiffe/go-spiffe/blob/v2.8.1/exp/proto/spiffe/broker/api.proto#L187-L203), and [214–217](https://github.com/spiffe/go-spiffe/blob/v2.8.1/exp/proto/spiffe/broker/api.proto#L214-L217).

### Descriptor set for the custom `Any`

Reflection can describe the Broker service, but the most deterministic `grpcurl` invocation supplies both the implemented Broker proto and the project-specific Incus message descriptor. Build one descriptor set:

```sh
REPO_ROOT=/Users/josh/code/componere/incusos-spire/.wt/feat-incus-attestor
GO_SPIFFE_DIR="$(go mod download -json github.com/spiffe/go-spiffe/v2@v2.8.1 | jq -r .Dir)"
PROTOSET=/tmp/incus-broker.protoset

protoc \
  -I "$GO_SPIFFE_DIR" \
  -I "$REPO_ROOT/proto" \
  --include_imports \
  --descriptor_set_out="$PROTOSET" \
  "$GO_SPIFFE_DIR/exp/proto/spiffe/broker/api.proto" \
  "$REPO_ROOT/proto/componere/incus/v1alpha1/reference.proto"
```

The implemented Broker proto comes from [`spiffe/go-spiffe@v2.8.1/exp/proto/spiffe/broker/api.proto`](https://github.com/spiffe/go-spiffe/blob/v2.8.1/exp/proto/spiffe/broker/api.proto), because SPIRE imports that generated package directly ([`service.go`, lines 11–12](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/broker/api/service.go#L11-L12)). `grpcurl` documents that JSON encoding uses descriptors and that `--include_imports` is required when creating a reusable protoset ([`fullstorydev/grpcurl/README.md`, “Descriptor Sources”](https://github.com/fullstorydev/grpcurl/blob/master/README.md#protoset-files)).

### Copy-pasteable Unix-socket invocation

First obtain the broker X.509-SVID through the host agent's Workload API and write its PEM certificate chain and unencrypted PEM key to the two paths below. Then run:

```sh
BROKER_SOCKET=/run/spire/broker-sockets/broker.sock
BROKER_SVID_CERT_PEM=/run/incus-broker/svid.pem
BROKER_SVID_KEY_PEM=/run/incus-broker/svid-key.pem
PROTOSET=/tmp/incus-broker.protoset

grpcurl \
  -unix \
  -insecure \
  -cert "$BROKER_SVID_CERT_PEM" \
  -key "$BROKER_SVID_KEY_PEM" \
  -rpc-header 'broker.spiffe.io: true' \
  -protoset "$PROTOSET" \
  -d @ \
  "$BROKER_SOCKET" \
  spiffe.broker.API/SubscribeToX509SVID <<'JSON'
{
  "reference": {
    "reference": {
      "@type": "type.googleapis.com/componere.incus.v1alpha1.IncusInstanceReference",
      "instanceUuid": "e9e6a2a0-d695-42d3-8e8c-92d290bfc7da",
      "project": "spike-spiffe",
      "generationUuid": "74957ed8-19bc-4d23-b76b-763bb6f8bb60",
      "server": "822b00ed474a2574d43223cbf34919b76a64946e145ec246aa4ae2e43318afdd"
    }
  }
}
JSON
```

`SubscribeToX509SVID` is server-streaming, so the command remains open for updates. Omit optional `project`, `generationUuid`, or `server` only when the frozen reference rules allow that omission.

`-insecure` is required for this diagnostic template because a SPIFFE X.509-SVID is authorized by URI SAN through SPIFFE-aware verification rather than conventional DNS-name verification. The endpoint still authenticates the client certificate. The go-spiffe TLS implementation itself sets `InsecureSkipVerify` and installs `VerifyPeerCertificate`, and states that SPIFFE TLS clients must disable hostname verification ([`spiffe/go-spiffe@v2.8.1/spiffetls/tlsconfig/config.go`, lines 58–74 and 184–190](https://github.com/spiffe/go-spiffe/blob/v2.8.1/spiffetls/tlsconfig/config.go#L58-L74)). A production broker must use SPIFFE-aware server authorization rather than copying this diagnostic `-insecure` setting.

Every call must send exactly one metadata value `broker.spiffe.io: true`. SPIRE checks `len(values) != 1 || values[0] != "true"` and returns `codes.InvalidArgument`, description `security header missing from request` ([`spiffe/spire@v1.15.2/pkg/agent/broker/endpoints.go`, lines 275–286](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/broker/endpoints.go#L275-L286)). To exercise the P7 negative case, rerun the command without `-rpc-header`; expect:

```text
rpc error: code = InvalidArgument desc = security header missing from request
```

## 2. Reflection behavior

Reflection **is enabled** in SPIRE 1.15.2. The server calls `reflection.Register(server)` after registering the Broker API ([`endpoints.go`, lines 144–151](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/broker/endpoints.go#L144-L151)). It is intentionally restricted to UDS; a reflection method over any non-Unix peer returns `PermissionDenied`, `server reflection is only available over Unix sockets` ([`endpoints.go`, lines 255–267](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/broker/endpoints.go#L255-L267)). The security-header middleware applies to reflection too.

Use the following reflection probe. The client certificate flags are mandatory because the whole gRPC server is behind mutual TLS:

```sh
grpcurl \
  -unix \
  -insecure \
  -cert "$BROKER_SVID_CERT_PEM" \
  -key "$BROKER_SVID_KEY_PEM" \
  -rpc-header 'broker.spiffe.io: true' \
  "$BROKER_SOCKET" \
  list
```

> Source quote: `server := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)), ...)`, followed by `reflection.Register(server)` ([`endpoints.go`, lines 137–151](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/broker/endpoints.go#L137-L151)).

The combined protoset remains the recommended path for the custom Incus `Any` because it explicitly supplies the vendor message descriptor as well as the service descriptor.

## 3. Exact agent Broker configuration

Use this block for the P7 UDS-only endpoint:

```hcl
agent {
    # Existing required agent settings remain here.

    experimental {
        broker {
            socket_path = "/run/spire/broker-sockets/broker.sock"

            # bind_address is intentionally omitted: there is no implicit TCP
            # address, so omission leaves the Broker endpoint UDS-only.
            brokers = [
                {
                    id = "spiffe://spike.incus.internal/incus-broker"
                    allowed_reference_types = [
                        {
                            type_url = "type.googleapis.com/componere.incus.v1alpha1.IncusInstanceReference"
                            allow_over_tcp = false
                        },
                    ]
                },
            ]
        }
    }
}
```

Requirements and defaults from source:

- The `experimental.broker` block is optional. Once present, at least one of `socket_path` or `bind_address` must be non-empty. Both may be set. There is **no default `bind_address`**: both fields are plain strings, and source returns `experimental.broker requires socket_path, bind_address, or both` when both remain empty ([`cmd/spire-agent/cli/run/run.go`, lines 134–184](https://github.com/spiffe/spire/blob/v1.15.2/cmd/spire-agent/cli/run/run.go#L134-L184)).
- `allow_over_tcp` defaults to `false` as the decoded Go `bool` zero value. Source states: “The default is false, so the reference type is only allowed over UDS” ([`run.go`, lines 163–171](https://github.com/spiffe/spire/blob/v1.15.2/cmd/spire-agent/cli/run/run.go#L163-L171)).
- `brokers` must contain at least one entry at runtime (`at least one broker is required`) ([`pkg/agent/broker/endpoints.go`, lines 122–127](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/broker/endpoints.go#L122-L127)).
- Each `id` is required, must parse as a SPIFFE ID, and must be unique. `allowed_reference_types` must be non-empty. Every entry requires non-empty `type_url`; `"*"` is allowed only as the sole item ([`run.go`, lines 203–220](https://github.com/spiffe/spire/blob/v1.15.2/cmd/spire-agent/cli/run/run.go#L203-L220) and [725–753](https://github.com/spiffe/spire/blob/v1.15.2/cmd/spire-agent/cli/run/run.go#L725-L753)).
- On POSIX, the Broker socket may not be in the Workload API socket's directory or a subdirectory; source returns `broker socket cannot be in the same directory or a subdirectory as that containing the Workload API socket` ([`cmd/spire-agent/cli/run/run_posix.go`, lines 58–72](https://github.com/spiffe/spire/blob/v1.15.2/cmd/spire-agent/cli/run/run_posix.go#L58-L72)).

## 4. Exact external WorkloadAttestor configuration

Configure the binary under the plugin name `incus`:

```hcl
plugins {
    WorkloadAttestor "incus" {
        plugin_cmd      = "/opt/spire/bin/incus-attestor"
        plugin_checksum = "<paste the 64-character lowercase SHA-256 hex digest>"

        plugin_data {
            # The fields inside this block are owned by the incus-attestor
            # implementation, not by SPIRE. An empty block is valid SPIRE HCL.
        }
    }
}
```

Compute and paste the checksum with:

```sh
shasum -a 256 /opt/spire/bin/incus-attestor | cut -d ' ' -f 1
```

SPIRE treats `plugin_checksum` as the hex-encoded SHA-256 digest of the binary. It applies `hex.DecodeString`, requires the decoded length to equal `sha256.New().Size()` (32 bytes, therefore 64 hex characters), and passes that digest and SHA-256 hash to go-plugin secure loading ([`pkg/common/catalog/external.go`, lines 33–34 and 188–202](https://github.com/spiffe/spire/blob/v1.15.2/pkg/common/catalog/external.go#L33-L34)). The parser permits omission but logs `Plugin checksum not configured` ([`external.go`, lines 58–65](https://github.com/spiffe/spire/blob/v1.15.2/pkg/common/catalog/external.go#L58-L65)); P7 should not omit it.

`plugin_cmd` is what makes this declaration external. `plugin_data` is plugin-specific and mutually exclusive with `plugin_data_file` ([`doc/spire_agent.md`, lines 225–230](https://github.com/spiffe/spire/blob/v1.15.2/doc/spire_agent.md#L225-L230)). If `plugin_data` is present, the plugin must advertise and implement the SDK Config service; the SDK authoring guide says SPIRE fails to load a configured plugin that does not implement that service ([`spiffe/spire-plugin-sdk@5dcde407c4d1/docs/AUTHORING.md`, lines 8–26](https://github.com/spiffe/spire-plugin-sdk/blob/5dcde407c4d1/docs/AUTHORING.md#L8-L26)).

### Selector prefix rule

The quoted plugin name **must be `incus`**. The plugin returns only selector values:

```go
[]string{
    "uuid:<value>",
    "generation:<value>",
    "project:<value>",
    "type:<value>",
    "name:<value>",
    "image:<value>",
}
```

SPIRE converts every returned value to `common.Selector{Type: v1.Name(), Value: value}` ([`pkg/agent/plugin/workloadattestor/v1.go`, lines 84–105](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/plugin/workloadattestor/v1.go#L84-L105)). The SDK proto also states twice that “the type of the selector is inferred from the plugin name” ([`workloadattestor.proto`, lines 31–35 and 46–49](https://github.com/spiffe/spire-plugin-sdk/blob/5dcde407c4d1/proto/spire/plugin/agent/workloadattestor/v1/workloadattestor.proto#L31-L35)). Returning `incus:uuid:<value>` from a plugin named `incus` would therefore produce the wrong selector `incus:incus:uuid:<value>`.

## 5. External plugin Go contract and `main()` wiring

Use the exact SDK dependency from SPIRE's `go.mod`:

```text
github.com/spiffe/spire-plugin-sdk v1.4.4-0.20260617144146-5dcde407c4d1
```

Imports:

```go
import (
    "github.com/spiffe/spire-plugin-sdk/pluginmain"
    workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
    configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
)
```

The internal plugin gRPC service is `spire.plugin.agent.workloadattestor.v1.WorkloadAttestor`; its full RPC name is `/spire.plugin.agent.workloadattestor.v1.WorkloadAttestor/AttestReference`. The generated server interface requires:

```go
AttestReference(
    context.Context,
    *workloadattestorv1.AttestReferenceRequest,
) (*workloadattestorv1.AttestReferenceResponse, error)
```

and requires embedding `workloadattestorv1.UnimplementedWorkloadAttestorServer` by value for forward compatibility ([`workloadattestor_grpc.pb.go`, lines 79–112](https://github.com/spiffe/spire-plugin-sdk/blob/5dcde407c4d1/proto/spire/plugin/agent/workloadattestor/v1/workloadattestor_grpc.pb.go#L79-L112)). The generated descriptor fixes the service name ([same file, lines 172–183](https://github.com/spiffe/spire-plugin-sdk/blob/5dcde407c4d1/proto/spire/plugin/agent/workloadattestor/v1/workloadattestor_grpc.pb.go#L172-L183)).

The request's Go field is `Reference *anypb.Any`; the response's Go field is `SelectorValues []string`. On the wire they are `google.protobuf.Any reference = 1` and `repeated string selector_values = 1` ([`workloadattestor.proto`, lines 38–49](https://github.com/spiffe/spire-plugin-sdk/blob/5dcde407c4d1/proto/spire/plugin/agent/workloadattestor/v1/workloadattestor.proto#L38-L49)). The implementation must compare `req.GetReference().GetTypeUrl()` with the frozen URL, unmarshal `req.GetReference()` into `IncusInstanceReference`, and return the six unprefixed `key:value` values in `SelectorValues`.

Minimal correct wiring when `plugin_data` is used:

```go
// Plugin embeds both generated Unimplemented...Server values, implements
// AttestReference, and implements configv1.ConfigServer.Configure.
func main() {
    plugin := new(Plugin)
    pluginmain.Serve(
        workloadattestorv1.WorkloadAttestorPluginServer(plugin),
        configv1.ConfigServiceServer(plugin),
    )
}
```

`WorkloadAttestorPluginServer` advertises plugin type `WorkloadAttestor` and calls `RegisterWorkloadAttestorServer` ([`workloadattestor_spire_plugin.pb.go`, lines 10–28](https://github.com/spiffe/spire-plugin-sdk/blob/5dcde407c4d1/proto/spire/plugin/agent/workloadattestor/v1/workloadattestor_spire_plugin.pb.go#L10-L28)). `pluginmain.Serve` accepts that plugin server plus zero or more service servers and does not return ([`pluginmain/serve.go`, lines 8–21](https://github.com/spiffe/spire-plugin-sdk/blob/5dcde407c4d1/pluginmain/serve.go#L8-L21)). The current generated Config wrapper is definitively named `ConfigServiceServer` ([`config_spire_service.pb.go`, lines 9–22](https://github.com/spiffe/spire-plugin-sdk/blob/5dcde407c4d1/proto/spire/service/common/config/v1/config_spire_service.pb.go#L9-L22)).

The plugin implements `AttestReference`; it may leave legacy `Attest` unimplemented through the embedded server. The proto explicitly defines `AttestReference` in this pinned SDK. A plugin that implements the RPC but receives a type it does not support must return `InvalidArgument`; `Unimplemented` means the plugin does not implement reference attestation at all ([`workloadattestor.proto`, lines 16–24](https://github.com/spiffe/spire-plugin-sdk/blob/5dcde407c4d1/proto/spire/plugin/agent/workloadattestor/v1/workloadattestor.proto#L16-L24)).

## 6. Reference-type authorization and attestor dispatch

SPIRE does **not** maintain a `type_url -> plugin` routing table. After the broker allowlist gate, the agent invokes `AttestReference` on **all configured workload attestors concurrently**. It skips a plugin only when that plugin returns `Unimplemented`; if every plugin is skipped, the agent returns `Unimplemented`, `no workload attestor handled reference` ([`pkg/agent/attestor/workload/workload.go`, lines 86–104 and 116–128](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/attestor/workload/workload.go#L86-L104)). Therefore:

1. `brokers[].allowed_reference_types[].type_url` must exactly equal `type.googleapis.com/componere.incus.v1alpha1.IncusInstanceReference` so the request passes the broker gate.
2. The `incus` plugin must exactly compare the incoming `Any.type_url` with that same URL and handle it.
3. Other reference-capable attestors receive the same `Any`; their correct response for an unsupported type is `InvalidArgument`, while legacy/non-reference plugins surface `Unimplemented` and are skipped.

For the P7 **disallowed type** negative case, authorization happens before attestation. Source returns exactly:

```go
status.Errorf(
    codes.PermissionDenied,
    "broker %q is not allowed to use reference type %q",
    caller,
    ref.GetTypeUrl(),
)
```

([`pkg/agent/broker/api/service.go`, lines 91–108](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/broker/api/service.go#L91-L108)). Expected UDS result:

```text
rpc error: code = PermissionDenied desc = broker "spiffe://spike.incus.internal/incus-broker" is not allowed to use reference type "<submitted-type-url>"
```

A missing or empty `type_url` instead yields `InvalidArgument`, `workload reference must be provided` ([`service.go`, lines 94–99](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/broker/api/service.go#L94-L99)). Once attestation runs, SPIRE preserves a plugin's gRPC status (`InvalidArgument`, `NotFound`, `PermissionDenied`, and so on); only a non-status error is converted to `Unauthenticated`, `workload attestation failed: ...` ([`service.go`, lines 361–376](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/broker/api/service.go#L361-L376)).

## 7. Broker authentication and unauthorized-ID failure

The Broker endpoint always uses mutual TLS with X.509-SVIDs. SPIRE source says clients are expected to obtain their SVIDs from the Workload API first. It constructs:

```go
tlsconfig.MTLSServerConfig(
    e.c.SVIDSource,
    e.c.BundleSource,
    tlsconfig.AuthorizeOneOf(brokerIDs...),
)
```

and supplies that TLS config to the gRPC server ([`pkg/agent/broker/endpoints.go`, lines 129–145](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/broker/endpoints.go#L129-L145)). For this spike, the certificate's SPIFFE ID must be exactly:

```text
spiffe://spike.incus.internal/incus-broker
```

because that is the configured `brokers[].id`. `AuthorizeOneOf` adapts `spiffeid.MatchOneOf` ([`spiffe/go-spiffe@v2.8.1/spiffetls/tlsconfig/authorizer.go`, lines 25–38](https://github.com/spiffe/go-spiffe/blob/v2.8.1/spiffetls/tlsconfig/authorizer.go#L25-L38)); a non-member produces `unexpected ID "<actual-id>"` ([`spiffeid/match.go`, lines 25–38](https://github.com/spiffe/go-spiffe/blob/v2.8.1/spiffeid/match.go#L25-L38)). The TLS verifier returns that authorizer error from `VerifyPeerCertificate` during the handshake ([`spiffetls/tlsconfig/config.go`, lines 110–127 and 170–180](https://github.com/spiffe/go-spiffe/blob/v2.8.1/spiffetls/tlsconfig/config.go#L110-L127)).

**Exact negative-case interpretation:** an otherwise valid X.509-SVID with an unconfigured SPIFFE ID is rejected during TLS peer authorization, before a Broker RPC reaches `getCallerContext`. Therefore the server returns **no gRPC code** for an unauthorized broker ID. The test must assert TLS/transport handshake failure, not `PermissionDenied` or `Unauthenticated`. `Unauthenticated` in `getCallerContext` applies only after an RPC reaches the service without usable TLS peer identity ([`service.go`, lines 132–147](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/broker/api/service.go#L132-L147)).

`[UNVERIFIED]` The exact text and synthetic status that a particular `grpcurl` build prints for this pre-RPC TLS failure are client-version dependent and are not fixed by SPIRE source. Settle it in P7 by obtaining a valid SVID for an ID not present in `brokers[]`, invoking the UDS command with that cert/key, and capturing both `grpcurl` stderr and the agent TLS log. The server-side acceptance criterion is the failed TLS handshake and absence of an attestor call.

## 8. Version-specific footguns and source-over-doc decisions

1. **Experimental/incubating surface.** SPIRE documents the whole Broker block as experimental and warns that breaking changes may land before stabilization ([`doc/spire_agent.md`, lines 563–566](https://github.com/spiffe/spire/blob/v1.15.2/doc/spire_agent.md#L563-L566)). The SPIFFE standard labels the API “Stability: Incubating” ([`SPIFFE_Broker_API.md`, lines 1–3](https://github.com/spiffe/spiffe/blob/dc4e9d9b4eff8aa181a54cd330ff9f877186060e/standards/SPIFFE_Broker_API.md#L1-L3)). Pin SPIRE and the two SDK versions and rerun all P7 acceptance cases on any bump.

2. **SPIRE docs show a non-working mTLS reflection command.** `doc/spire_agent.md` shows `grpcurl -unix -rpc-header ... /path/to/broker.sock list` without client certificate flags ([lines 614–628](https://github.com/spiffe/spire/blob/v1.15.2/doc/spire_agent.md#L614-L628)). Source applies `grpc.Creds(credentials.NewTLS(tlsConfig))` to the entire server, including reflection ([`endpoints.go`, lines 134–151](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/broker/endpoints.go#L134-L151)). Trust source: use `-cert`, `-key`, and the diagnostic server-verification treatment shown above.

3. **The documented checksum example is the wrong length.** The agent docs example uses `4e1243bd22c66e76c2ba9eddc1f91394e57f9f83`, a 40-character value ([`doc/spire_agent.md`, lines 249–260](https://github.com/spiffe/spire/blob/v1.15.2/doc/spire_agent.md#L249-L260)). Source requires a 32-byte SHA-256 digest decoded from **64 hex characters** ([`external.go`, lines 188–202](https://github.com/spiffe/spire/blob/v1.15.2/pkg/common/catalog/external.go#L188-L202)). Trust source.

4. **The pinned SDK authoring guide names a stale Config helper.** `docs/AUTHORING.md` shows `configv1.ConfigPluginServer(plugin)` ([lines 45–53](https://github.com/spiffe/spire-plugin-sdk/blob/5dcde407c4d1/docs/AUTHORING.md#L45-L53)), but the generated code in the same commit exports `ConfigServiceServer` ([`config_spire_service.pb.go`, lines 9–22](https://github.com/spiffe/spire-plugin-sdk/blob/5dcde407c4d1/proto/spire/service/common/config/v1/config_spire_service.pb.go#L9-L22)). Trust generated source and use `ConfigServiceServer`.

5. **Allowlist rejection differs from an unsupported reference.** A configured broker using a type outside its allowlist gets `PermissionDenied` before any plugin call ([`service.go`, lines 91–108](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/broker/api/service.go#L91-L108)). An allowlisted type that no plugin handles currently becomes `Unimplemented`, `no workload attestor handled reference` ([`workload.go`, lines 86–104](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/attestor/workload/workload.go#L86-L104)), even though the SPIFFE standard says a server that does not recognize a reference type must reject it with `InvalidArgument` ([`SPIFFE_Broker_API.md`, lines 215–219](https://github.com/spiffe/spiffe/blob/dc4e9d9b4eff8aa181a54cd330ff9f877186060e/standards/SPIFFE_Broker_API.md#L215-L219)). Trust SPIRE 1.15.2 source for tests.

6. **There is fan-out, not exclusive routing.** Every configured attestor receives `AttestReference` concurrently; `type_url` does not select one plugin in the agent ([`workload.go`, lines 86–104 and 116–128](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/attestor/workload/workload.go#L86-L104)). The Incus plugin must make its exact type check explicit, and the P7 tests must not assume other configured attestors are bypassed.

7. **Reflection is UDS-only and header-gated.** It is present, contrary to any assumption that an experimental endpoint omits it, but TCP reflection returns `PermissionDenied`, and UDS reflection without the mandatory header returns `InvalidArgument` ([`endpoints.go`, lines 255–286](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/broker/endpoints.go#L255-L286)).
