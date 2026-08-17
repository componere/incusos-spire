> **Read-only delivery note:** I could not write this file myself. This is the complete Markdown for the orchestrator to write to `.journal/001/evidence/p9/X509POP_BRIEF.md`. I made no file changes and did not access the live Incus host.

# SPIRE 1.15.2 `x509pop` `mode="spiffe"` exchange brief

## Direct answer

The P9 flow is supported, but three details are load-bearing:

1. **The source-level server key is `spiffe_prefix`, not the documented `svid_prefix`.** At `v1.15.2`, the server struct binds `SVIDPrefix` to `hcl:"spiffe_prefix"`; use `spiffe_prefix = "/spire-exchange"` or omit it and take the default. The upstream server document says `svid_prefix`, but that name is not bound by the implementation. [Server source, `Config`](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/plugin/nodeattestor/x509pop/x509pop.go#L48-L57) and [server document](https://github.com/spiffe/spire/blob/v1.15.2/doc/plugin_server_nodeattestor_x509pop.md#L16-L29).
2. **The real default template has a required leading slash:** `"/{{ .PluginName }}/{{ .SVIDPathTrimmed }}"`. The document omits that slash. The leading slash is required because `idutil.AgentID` validates the template result as an absolute path suffix before prefixing `/spire/agent`. [Shared defaults](https://github.com/spiffe/spire/blob/v1.15.2/pkg/common/plugin/x509pop/x509pop.go#L24-L28), [`AgentID`](https://github.com/spiffe/spire/blob/v1.15.2/pkg/common/idutil/spiffeid.go#L40-L55), and [the incorrect document table](https://github.com/spiffe/spire/blob/v1.15.2/doc/plugin_server_nodeattestor_x509pop.md#L88-L100).
3. **A SPIRE-issued X509-SVID is definitively usable as the exchange credential: yes.** SPIRE workload SVIDs have `digitalSignature` key usage; the server verifies the presented chain with `ExtKeyUsageAny`; and the proof-of-possession implementation supports the RSA and ECDSA key types SPIRE uses. The upstream tests explicitly exercise a Workload-API-fetched X509-SVID as the `x509pop` credential and a SPIFFE-mode exchange certificate on the server. [SPIRE SVID template](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/credtemplate/builder.go#L444-L472), [server verification](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/plugin/nodeattestor/x509pop/x509pop.go#L247-L300), [agent Workload API test](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/plugin/nodeattestor/x509pop/x509pop_test.go#L76-L143), and [server SPIFFE-exchange test](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/plugin/nodeattestor/x509pop/x509pop_test.go#L105-L188).

The exact mapping is:

```text
exchange SVID URI SAN:
  spiffe://spike.incus.internal/spire-exchange/incus/<instance-uuid>

EscapedPath():
  /spire-exchange/incus/<instance-uuid>

remove normalized prefix "/spire-exchange/":
  incus/<instance-uuid>

default template "/{{ .PluginName }}/{{ .SVIDPathTrimmed }}":
  /x509pop/incus/<instance-uuid>

idutil.AgentID adds "/spire/agent":
  spiffe://spike.incus.internal/spire/agent/x509pop/incus/<instance-uuid>
```

That derivation comes directly from the prefix/trimming code, the shared template, and `idutil.AgentID`; it is not inferred from the documentation table. [Prefix/trimming](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/plugin/nodeattestor/x509pop/x509pop.go#L319-L355), [template execution](https://github.com/spiffe/spire/blob/v1.15.2/pkg/common/plugin/x509pop/x509pop.go#L252-L276), and [`AgentID`](https://github.com/spiffe/spire/blob/v1.15.2/pkg/common/idutil/spiffeid.go#L40-L55).

## 1. Guest-agent configuration and credential files

### Exact `NodeAttestor "x509pop"` keys

For P9's file-delivered credential, the guest plugin block needs:

```hcl
NodeAttestor "x509pop" {
    plugin_data {
        private_key_path  = "/run/incus-spiffe-bootstrap/exchange-key.pem"
        certificate_path  = "/run/incus-spiffe-bootstrap/exchange-chain.pem"
        # Only set this if intermediates are not already in certificate_path:
        # intermediates_path = "/run/incus-spiffe-bootstrap/exchange-intermediates.pem"
    }
}
```

The source exposes exactly four plugin keys:

```go
type Config struct {
    PrivateKeyPath       string `hcl:"private_key_path"`
    CertificatePath      string `hcl:"certificate_path"`
    IntermediatesPath    string `hcl:"intermediates_path"`
    SpiffeEndpointSocket string `hcl:"spiffe_endpoint_socket"`
}
```

When `spiffe_endpoint_socket` is empty, `private_key_path` and `certificate_path` are required. P9 is using delivered files, so it should not set `spiffe_endpoint_socket`; that alternative makes the plugin fetch an SVID from another Workload API at attestation time. [Agent plugin config and validation](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/plugin/nodeattestor/x509pop/x509pop.go#L43-L69).

There is **no trust-bundle key in `x509pop` `plugin_data`**. `trust_bundle_path` is a top-level `agent { ... }` setting used to authenticate the SPIRE Server connection; it is covered in section 5. [Agent run config](https://github.com/spiffe/spire/blob/v1.15.2/cmd/spire-agent/cli/run/run.go#L74-L104).

### What the loader actually accepts

The decisive plugin loading code is:

```go
certificate, err := tls.LoadX509KeyPair(config.CertificatePath, config.PrivateKeyPath)
if err != nil {
    return nil, status.Errorf(codes.InvalidArgument, "unable to load keypair: %v", err)
}

privateKey = certificate.PrivateKey
certificates = certificate.Certificate

if strings.TrimSpace(config.IntermediatesPath) != "" {
    intermediates, err := util.LoadCertificates(config.IntermediatesPath)
    // ...
    for _, cert := range intermediates {
        certificates = append(certificates, cert.Raw)
    }
}
```

[Agent loader](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/plugin/nodeattestor/x509pop/x509pop.go#L151-L205).

Consequences:

- **Certificate and key files must be PEM, not raw DER.** `tls.LoadX509KeyPair` says both files contain PEM and collects every `CERTIFICATE` block in the certificate file. [Go 1.26.4 `LoadX509KeyPair`](https://github.com/golang/go/blob/go1.26.4/src/crypto/tls/tls.go#L231-L300). SPIRE `v1.15.2` itself declares Go 1.26.4. [`go.mod`](https://github.com/spiffe/spire/blob/v1.15.2/go.mod#L1-L4).
- `certificate_path` must contain at least the leaf certificate. It **may** contain the chain: the first `CERTIFICATE` block is the leaf, and following blocks are presented in order as intermediates. The root does not need to be in this file because SPIFFE mode obtains trust roots from the server's own bundle. [Go loader](https://github.com/golang/go/blob/go1.26.4/src/crypto/tls/tls.go#L231-L300) and [server roots/intermediates construction](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/plugin/nodeattestor/x509pop/x509pop.go#L203-L276).
- `intermediates_path` is optional and its PEM certificates are appended after everything already in `certificate_path`. Do not duplicate a chain between the two paths: the server counts every presented certificate after the leaf against `max_intermediates`, whose default is four. [Agent loader](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/plugin/nodeattestor/x509pop/x509pop.go#L174-L198) and [server limit](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/plugin/nodeattestor/x509pop/x509pop.go#L184-L214).
- The private key may be unencrypted PEM containing PKCS#1 RSA, PKCS#8 RSA/ECDSA, or SEC1 EC. The Go loader tries `ParsePKCS1PrivateKey`, `ParsePKCS8PrivateKey`, then `ParseECPrivateKey`, and checks that it matches the leaf public key. [Go 1.26.4 key parser](https://github.com/golang/go/blob/go1.26.4/src/crypto/tls/tls.go#L301-L389). Encrypted PEM is not decrypted by this path.
- Although the Go loader can parse PKCS#8 Ed25519, `x509pop` proof-of-possession only implements RSA and ECDSA. An Ed25519 exchange SVID therefore loads but fails at challenge generation as an unsupported public-key type. [Go key parser](https://github.com/golang/go/blob/go1.26.4/src/crypto/tls/tls.go#L338-L389) and [`GenerateChallenge`](https://github.com/spiffe/spire/blob/v1.15.2/pkg/common/plugin/x509pop/x509pop.go#L83-L112).

The broker contract supplies an unencrypted PKCS#8 DER key, DER certificate chain, and DER bundle. Therefore the guest harness must, without logging any bytes:

1. PEM-wrap the key as one `PRIVATE KEY` block.
2. Parse the certificate chain and write one `CERTIFICATE` PEM block per certificate, leaf first, to `certificate_path`.
3. Parse the bundle and write every authority as a `CERTIFICATE` PEM block to the top-level `trust_bundle_path`.

Raw `KeyDER`, `ChainDER`, or `BundleDER` files are not accepted by these file-loading paths. The exchange directory and files must be on tmpfs per the P9 security policy; the private key must never be printed, logged, copied into the journal, or written to persistent guest disk (`SPIKE_PLAN.md:233-247,372-378`). This remains a design tradeoff, not a solved production key-delivery design.

## 2. Server requirements in `mode="spiffe"`

### Correct server configuration

Use the source-level key name:

```hcl
NodeAttestor "x509pop" {
    plugin_data {
        mode                    = "spiffe"
        spiffe_prefix           = "/spire-exchange"
        agent_path_template     = "/{{ .PluginName }}/{{ .SVIDPathTrimmed }}"
        # ca_bundle_path(s) must not be set in spiffe mode.
    }
}
```

Both `spiffe_prefix` and `agent_path_template` can be omitted because those values are the source defaults. Explicit values make the live evidence easier to audit, but the template must retain its leading slash. [Server configuration source](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/plugin/nodeattestor/x509pop/x509pop.go#L48-L153).

In SPIFFE mode the source rejects `ca_bundle_path` and `ca_bundle_paths`. Instead, on each attestation it calls the server IdentityProvider host service, parses all returned `X509Authorities`, and makes them the root pool. [Mode configuration](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/plugin/nodeattestor/x509pop/x509pop.go#L75-L121) and [`getTrustBundle`](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/plugin/nodeattestor/x509pop/x509pop.go#L386-L414).

### Chain verification

The payload is an ordered slice of DER certificates; index 0 is the leaf and all later entries are loaded into an intermediate pool. Verification is exactly:

```go
chains, err := leaf.Verify(x509.VerifyOptions{
    Intermediates: intermediates,
    Roots:         trustBundle,
    KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
})
if err != nil {
    return status.Errorf(codes.PermissionDenied,
        "certificate verification failed: %v", err)
}
```

[Server attestation](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/plugin/nodeattestor/x509pop/x509pop.go#L184-L276).

Thus normal X.509 verification applies, including validity time, signatures, CA constraints, and a chain to a current server trust-bundle authority. `ExtKeyUsageAny` deliberately imposes no client-auth/server-auth EKU restriction. The separate proof-of-possession check does require `KeyUsageDigitalSignature`; see section 4. [Server verification and challenge creation](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/plugin/nodeattestor/x509pop/x509pop.go#L247-L300) and [challenge helper](https://github.com/spiffe/spire/blob/v1.15.2/pkg/common/plugin/x509pop/x509pop.go#L83-L112).

### SPIFFE URI SAN selection and prefix matching

After chain and proof verification, the server:

```go
var spiffeURIs []*url.URL
for _, uri := range leaf.URIs {
    if uri.Scheme == "spiffe" {
        spiffeURIs = append(spiffeURIs, uri)
    }
}
if len(spiffeURIs) == 0 {
    return status.Errorf(codes.PermissionDenied, "valid SVID x509 cert not found")
}
svidPath = spiffeURIs[0].EscapedPath()
if !strings.HasPrefix(svidPath, config.svidPrefix) {
    return status.Errorf(codes.PermissionDenied, "x509 cert doesnt match SVID prefix")
}
svidPath = strings.TrimPrefix(svidPath, config.svidPrefix)
```

[Server URI handling](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/plugin/nodeattestor/x509pop/x509pop.go#L319-L345).

Important consequences:

- The server uses the **first** URI SAN whose scheme is exactly `spiffe`; it does not require exactly one.
- It matches only `EscapedPath()`. It does not parse the URI with `x509svid.IDFromCert`, and this block does not compare the URI authority/trust domain with the configured trust domain. The SPIRE-issued P9 certificate is still constrained at issuance to the local trust domain by `BuildWorkloadX509SVIDTemplate`; nevertheless, the x509pop check itself is path-only. [URI handling](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/plugin/nodeattestor/x509pop/x509pop.go#L319-L345) and [SPIRE issuer trust-domain check](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/credtemplate/builder.go#L444-L457).
- The source default is `"/spire-exchange/"`, including the trailing slash. A configured value gets a trailing slash appended if missing. [Prefix initialization](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/plugin/nodeattestor/x509pop/x509pop.go#L130-L138).
- **The leading slash matters.** `EscapedPath()` begins with `/`; `spiffe_prefix = "spire-exchange"` normalizes to `"spire-exchange/"` and cannot match `/spire-exchange/...`.
- Setting the source-correct `spiffe_prefix = ""` normalizes to `/`, rather than storing an empty string. This still admits every conforming absolute SPIFFE path, then trims its initial slash. That is functionally broad, but it differs from the document's description of an empty prefix. [Prefix initialization](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/plugin/nodeattestor/x509pop/x509pop.go#L130-L138) and [document claim](https://github.com/spiffe/spire/blob/v1.15.2/doc/plugin_server_nodeattestor_x509pop.md#L69-L86).

## 3. Resulting node SPIFFE ID and edge cases

The shared source declares:

```go
var DefaultAgentPathTemplateSVID =
    agentpathtemplate.MustParse("/{{ .PluginName }}/{{ .SVIDPathTrimmed }}")
```

It executes the template with `PluginName: "x509pop"` and the already-trimmed path, then calls `idutil.AgentID(td, agentPath)`. [Shared x509pop helper](https://github.com/spiffe/spire/blob/v1.15.2/pkg/common/plugin/x509pop/x509pop.go#L24-L28) and [`MakeAgentID`](https://github.com/spiffe/spire/blob/v1.15.2/pkg/common/plugin/x509pop/x509pop.go#L252-L276).

`AgentID` requires an absolute suffix and constructs:

```go
if err := spiffeid.ValidatePath(suffix); err != nil { ... }
return spiffeid.FromPath(td, "/spire/agent"+suffix)
```

[`idutil.AgentID`](https://github.com/spiffe/spire/blob/v1.15.2/pkg/common/idutil/spiffeid.go#L40-L55).

For P9:

```text
spiffe://spike.incus.internal/spire-exchange/incus/<uuid>
                                └─ trim /spire-exchange/ ─┘
SVIDPathTrimmed = "incus/<uuid>"
template output = "/x509pop/incus/<uuid>"
node ID = "spiffe://spike.incus.internal/spire/agent/x509pop/incus/<uuid>"
```

Edge cases are source-determined:

- An exchange ID ending exactly at `/spire-exchange/` trims to empty, making the default suffix `/x509pop/`; `ValidatePath` rejects a trailing slash. [go-spiffe path validation](https://github.com/spiffe/go-spiffe/blob/v2.8.1/spiffeid/path.go#L28-L73).
- A doubled slash after the prefix trims to a leading slash and produces `/x509pop//...`; `ValidatePath` rejects the empty segment. [go-spiffe path validation](https://github.com/spiffe/go-spiffe/blob/v2.8.1/spiffeid/path.go#L28-L73).
- `EscapedPath()` preserves percent encoding, while SPIFFE path validation permits only its defined segment characters. P9's literal `incus/<UUID>` uses only safe characters and avoids this issue. [URI trimming](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/plugin/nodeattestor/x509pop/x509pop.go#L319-L345) and [path-character validation](https://github.com/spiffe/go-spiffe/blob/v2.8.1/spiffeid/path.go#L28-L87).
- A custom template copied verbatim from the upstream document, without the initial `/`, fails because the suffix is not absolute. The source default is correct; the document table is wrong. [Shared default](https://github.com/spiffe/spire/blob/v1.15.2/pkg/common/plugin/x509pop/x509pop.go#L24-L28), [`AgentID`](https://github.com/spiffe/spire/blob/v1.15.2/pkg/common/idutil/spiffeid.go#L40-L55), and [document table](https://github.com/spiffe/spire/blob/v1.15.2/doc/plugin_server_nodeattestor_x509pop.md#L88-L100).

The referenced template-engine document says agent path templates use Go `text/template` plus a restricted Sprig function set; P9 does not need any custom function. [Template-engine document](https://github.com/spiffe/spire/blob/v1.15.2/doc/template_engine.md) and [allowed functions/parser](https://github.com/spiffe/spire/blob/v1.15.2/pkg/common/agentpathtemplate/template.go#L10-L157).

## 4. Proof of possession and X509-SVID suitability

### Exact protocol

1. The agent sends the DER certificate list.
2. The server verifies the chain.
3. The server generates a cryptographically random 32-byte challenge nonce, selected according to the leaf public key type.
4. The agent generates its own random 32-byte response nonce.
5. Both calculate `SHA-256(server_nonce || agent_nonce)`.
6. The agent signs that 32-byte digest with the private key matching the leaf certificate.
7. The server verifies with the leaf public key.

The nonce length and hash are:

```go
const nonceLen = 32
// ...
h := sha256.New()
h.Write(challenge)
h.Write(response)
return h.Sum(nil), nil
```

[Shared nonce helper](https://github.com/spiffe/spire/blob/v1.15.2/pkg/common/plugin/x509pop/x509pop.go#L18-L23) and [`combineNonces`](https://github.com/spiffe/spire/blob/v1.15.2/pkg/common/plugin/x509pop/x509pop.go#L311-L328).

For RSA, the agent uses RSA-PSS with SHA-256 and default PSS options, and returns the agent nonce plus the signature:

```go
signature, err := rsa.SignPSS(
    rand.Reader, privateKey, crypto.SHA256, combined, nil)
```

The server recomputes the digest and calls `rsa.VerifyPSS(..., crypto.SHA256, ..., nil)`. [RSA response and verification](https://github.com/spiffe/spire/blob/v1.15.2/pkg/common/plugin/x509pop/x509pop.go#L166-L207).

For ECDSA, the agent signs the same digest with `ecdsa.Sign`, returning the agent nonce plus `R` and `S`; the server reconstructs the integers and calls `ecdsa.Verify`. [ECDSA response and verification](https://github.com/spiffe/spire/blob/v1.15.2/pkg/common/plugin/x509pop/x509pop.go#L209-L251).

The certificate's public-key type determines the server challenge; the loaded private-key type determines the agent response. Only RSA and ECDSA are supported. [Challenge selection and response selection](https://github.com/spiffe/spire/blob/v1.15.2/pkg/common/plugin/x509pop/x509pop.go#L83-L145).

### Key-usage and EKU decision

Before creating any challenge, the server requires:

```go
if (cert.KeyUsage & x509.KeyUsageDigitalSignature) == 0 {
    return nil, errors.New("certificate not intended for digital signature use")
}
```

[`GenerateChallenge`](https://github.com/spiffe/spire/blob/v1.15.2/pkg/common/plugin/x509pop/x509pop.go#L83-L112).

There is no restrictive extended-key-usage check: chain verification passes `KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}`. [Server verification](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/plugin/nodeattestor/x509pop/x509pop.go#L260-L276).

**Definitive answer: yes, a SPIRE-issued X509-SVID can serve as the `x509pop` credential in `mode="spiffe"`, provided its key is RSA or ECDSA and its URI SAN path matches the prefix.** SPIRE's workload-SVID template sets:

```go
tmpl.KeyUsage = x509.KeyUsageKeyEncipherment |
    x509.KeyUsageKeyAgreement |
    x509.KeyUsageDigitalSignature
tmpl.ExtKeyUsage = []x509.ExtKeyUsage{
    x509.ExtKeyUsageServerAuth,
    x509.ExtKeyUsageClientAuth,
}
```

[SPIRE SVID template](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/credtemplate/builder.go#L444-L472).

This is also covered by upstream behavior tests: the agent test fetches an X509-SVID from a fake Workload API and successfully answers an x509pop challenge, while the server test's `success with spiffe exchange` case produces `spiffe://example.org/spire/agent/x509pop/testhost`. [Agent test](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/plugin/nodeattestor/x509pop/x509pop_test.go#L76-L143) and [server test](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/plugin/nodeattestor/x509pop/x509pop_test.go#L105-L188).

## 5. Guest trust-bundle bootstrap

`trust_bundle_path` belongs in the guest's top-level agent configuration:

```hcl
agent {
    trust_domain       = "spike.incus.internal"
    trust_bundle_path  = "/run/incus-spiffe-bootstrap/trust-bundle.pem"
    trust_bundle_format = "pem" # this is already the default
}
```

The agent requires either `trust_bundle_path` or `trust_bundle_url` unless `insecure_bootstrap` is enabled; these choices are mutually exclusive. P9 should use the delivered bundle and must not use insecure bootstrap. [Agent validation](https://github.com/spiffe/spire/blob/v1.15.2/cmd/spire-agent/cli/run/run.go#L385-L434).

The default format is `pem`. The bundle loader reads the whole file, calls `pemutil.ParseCertificates`, rejects an empty result, and accepts all certificate blocks returned by that parser. [Default format](https://github.com/spiffe/spire/blob/v1.15.2/cmd/spire-agent/cli/run/run.go#L926-L936), [bundle loading/parsing](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/trustbundlesources/bundle.go#L125-L214), and [multi-certificate PEM parser](https://github.com/spiffe/spire/blob/v1.15.2/pkg/common/pemutil/certs.go#L22-L44).

Therefore:

- The file may contain **one or many** `CERTIFICATE` PEM blocks.
- Raw DER is not directly usable with the default `pem` format.
- `trust_bundle_format = "spiffe"` expects a serialized SPIFFE bundle parsed by `bundleutil.Unmarshal`; it does not make a concatenated DER bundle acceptable. [Format constants and parser](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/trustbundlesources/config.go#L1-L12) and [`parseTrustBundle`](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/trustbundlesources/bundle.go#L239-L257).
- Consequently, the broker-delivered `BundleDER` is **not directly usable as `trust_bundle_path`**. Every DER authority must be converted to a PEM `CERTIFICATE` block. SPIRE's own PEM encoder does exactly one block per certificate. [PEM encoder](https://github.com/spiffe/spire/blob/v1.15.2/pkg/common/pemutil/certs.go#L34-L72).

The bootstrap bundle authenticates the SPIRE Server TLS connection, independently of the exchange certificate's chain. The client constructs a bundle source from those authorities and authorizes exactly the server ID `spiffe://<trust-domain>/spire/server`. [Agent TLS client](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/client/dial.go#L39-L76).

If the bundle and server disagree, the agent does **not** accept the server or silently replace the bootstrap trust root. An unknown-authority error takes the explicit retry/rebootstrap path:

```go
if x509util.IsUnknownAuthorityError(err) {
    if a.c.TrustBundleSources.IsBootstrap() {
        a.c.Log.Info("Trust Bundle and Server don't agree, bootstrapping again")
    } else if a.c.RebootstrapMode != RebootstrapNever {
        // wait for rebootstrap_delay, then clear the cached bundle
    }
}
```

A server `PermissionDenied` response exits immediately. [Agent bootstrap loop](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/agent.go#L184-L260). For the first P9 boot, a wrong PEM bundle therefore prevents the TLS-authenticated attestation connection; it is not a recoverable trust downgrade.

## 6. Server-produced `x509pop` selectors

The server returns `CanReattest: true` and `SelectorValues: buildSelectorValues(...)`. [Successful server response](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/plugin/nodeattestor/x509pop/x509pop.go#L346-L365).

`buildSelectorValues` emits:

```go
"subject:cn:" + leaf.Subject.CommonName
"ca:fingerprint:" + Fingerprint(cert)
"serialnumber:" + SerialNumberHex(leaf.SerialNumber)
"san:" + sanUriKey + ":" + sanUriValue
```

The Common Name selector is omitted if the CN is empty. CA fingerprints are SHA-1 fingerprints of every certificate in each verified chain except the leaf, de-duplicated across chains. The serial number is lowercase hexadecimal, padded to an even number of hex characters. SAN selectors come only from leaf URIs beginning `x509pop://<configured-trust-domain>/`; the first path segment is the key and the remainder is the value. [Selector construction and URI parsing](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/plugin/nodeattestor/x509pop/x509pop.go#L417-L474), [fingerprint/serial helpers](https://github.com/spiffe/spire/blob/v1.15.2/pkg/common/plugin/x509pop/x509pop.go#L244-L287).

The node-attestor adapter prefixes these values with selector type `x509pop`; the upstream success test expects values such as:

```text
x509pop:subject:cn:COMMONNAME
x509pop:ca:fingerprint:<sha1>
x509pop:serialnumber:0a1b2c3d4e7f
x509pop:san:datacenter:us-east-1
```

[Server test's expected selectors](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/plugin/nodeattestor/x509pop/x509pop_test.go#L164-L184).

A normal SPIRE-issued exchange SVID has a `spiffe:` URI SAN, not an `x509pop:` URI SAN, so **the exchange SPIFFE ID/path does not become an x509pop selector**. The default SPIRE workload-SVID subject has country and organization but no Common Name, absent DNS-name/custom-subject composition. [x509pop SAN parser](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/plugin/nodeattestor/x509pop/x509pop.go#L455-L474) and [default SVID subject](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/credtemplate/builder.go#L50-L63).

For P9, parent the guest workload registration entry on the stable, derived node ID:

```text
spiffe://spike.incus.internal/spire/agent/x509pop/incus/<instance-uuid>
```

Do not expect a stable `x509pop:spiffe-id` or `x509pop:uuid` node selector: neither exists. The serial-number selector changes with the exchange credential, while CA fingerprints identify issuers rather than the instance. Guest workload selectors remain the guest-local WorkloadAttestor selectors (for example `unix:*`), separate from these node-attestation selectors.

## 7. Re-attestation and restart behavior

### The plugin is re-attestable

The server returns:

```go
AgentAttributes: &nodeattestorv1.AgentAttributes{
    SpiffeId:       spiffeid.String(),
    SelectorValues: buildSelectorValues(...),
    CanReattest:    true,
}
```

[Server success path](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/plugin/nodeattestor/x509pop/x509pop.go#L346-L365).

This has a stronger consequence than “the initial exchange works.” When an agent SVID needs rotation and its state says `Reattestable`, the rotator chooses full re-attestation rather than ordinary renewal:

```go
if state.Reattestable {
    err = r.reattest(ctx)
} else {
    err = r.rotateSVID(ctx)
}
```

The `reattest` method opens an authenticated server connection and calls `r.c.NodeAttestor.Attest(ctx, stream)` again. [Rotator decision and full re-attestation](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/svid/rotator.go#L190-L288).

The x509pop agent plugin reloads `certificate_path` and `private_key_path` on every `AidAttestation` call. Therefore a short-lived exchange certificate that has expired, or exchange files removed after first use, cannot support later full re-attestation. [Agent `AidAttestation`](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/plugin/nodeattestor/x509pop/x509pop.go#L72-L124) and [per-attestation load](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/plugin/nodeattestor/x509pop/x509pop.go#L144-L205).

If re-attestation fails until the current node SVID expires, the rotator treats the agent as unrecoverable without re-attestation; manager failure handling removes the node SVID and shuts down. [Expired-rotation handling](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/svid/rotator.go#L89-L130) and [manager re-attestation failure](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/manager/manager.go#L231-L272).

**P9 design implication:** “fresh nonce only per boot” is not sufficient for an indefinitely running agent if the exchange credential is deleted or expires before the agent's next full re-attestation. Source behavior requires a way to place a fresh exchange SVID/key in the tmpfs paths before every x509pop re-attestation, or else accept that rotation eventually fails. Persisting only the node SVID improves restart behavior but does not change `CanReattest: true` or eliminate future full re-attestation.

### Restart with cached node state

At startup the agent loads:

1. the cached bundle;
2. the cached node SVID and its `reattestable` flag;
3. all SVID keys from the KeyManager;
4. the key matching the cached node SVID.

If the SVID exists, the matching private key exists, and the node SVID is not expired, startup returns the cached SVID and does not invoke node attestation. If the cached node SVID is expired, the agent logs that it is expired, generates a new keypair, and performs new node attestation. [Node-attestor startup flow](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/attestor/node/node.go#L68-L157).

The standard storage file is `<data_dir>/agent-data.json`; it persists the node SVID chain, bundle, `reattestable` flag, and bootstrap state, but not the node private key. [Agent storage](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/storage/storage.go#L14-L110) and [JSON/data path](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/storage/storage.go#L164-L266). With the built-in disk KeyManager, keys are separately stored as PKCS#8 material in its configured `keys.json`. [Disk KeyManager](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/plugin/keymanager/disk/disk.go).

To avoid node re-attestation **on a restart**, the guest must therefore persist:

- `<data_dir>/agent-data.json` containing an unexpired node SVID and cached bundle;
- the disk KeyManager's `keys.json` containing the matching node-SVID private key;
- the same trust-domain/server configuration.

A memory KeyManager, lost data directory, missing cached bundle, missing matching key, or expired node SVID causes new node attestation. [Startup selection](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/attestor/node/node.go#L68-L157).

There is one important plugin-loading footgun: catalog configuration validates the x509pop key pair at process startup by calling `loadConfigData(ctx, newConfig, false)`, and the file branch still calls `tls.LoadX509KeyPair`. Thus, even when an unexpired cached node SVID would avoid attestation, missing exchange certificate/key files make plugin configuration fail before that cache can be used. An expired but syntactically valid exchange certificate passes this local loading step because no validity check is done there; it fails later at server `leaf.Verify` if actual re-attestation is needed. [Agent plugin `Configure`](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/plugin/nodeattestor/x509pop/x509pop.go#L126-L142) and [loader](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/plugin/nodeattestor/x509pop/x509pop.go#L151-L205).

Therefore, after a guest reboot:

- **Valid persisted node SVID/key/bundle + parseable exchange files:** the agent can start without x509pop attestation, even if the exchange certificate is now expired; later full re-attestation still fails unless the files are refreshed.
- **Valid persisted node SVID/key/bundle + exchange files absent because tmpfs was cleared:** plugin configuration fails before cache reuse.
- **Expired or unusable persisted node SVID + expired exchange certificate:** startup attempts x509pop and the server returns `PermissionDenied` because certificate verification fails.
- **No persisted node SVID/key:** a fresh exchange credential is required.

The persistent node SVID and its private key are ordinary agent state and are distinct from the exchange private key. P9's rule forbids only the exchange private key from persistent guest disk; the experiment must record the security tradeoff rather than claim the exchange credential lifecycle is solved (`SPIKE_PLAN.md:233-247,372-378`).

## 8. Version footguns: source wins over prose

| Topic | `v1.15.2` prose | `v1.15.2` source contract | P9 action |
|---|---|---|---|
| Prefix config key | `svid_prefix` | `hcl:"spiffe_prefix"` | Use `spiffe_prefix`. Do not copy the documented key. [Source](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/plugin/nodeattestor/x509pop/x509pop.go#L48-L57), [doc](https://github.com/spiffe/spire/blob/v1.15.2/doc/plugin_server_nodeattestor_x509pop.md#L16-L29). |
| Default SPIFFE-mode template | `{{ .PluginName }}/{{ .SVIDPathTrimmed }}` | `/{{ .PluginName }}/{{ .SVIDPathTrimmed }}` | Preserve the source's leading `/`; a custom template without it fails absolute-path validation. [Source](https://github.com/spiffe/spire/blob/v1.15.2/pkg/common/plugin/x509pop/x509pop.go#L24-L28), [doc](https://github.com/spiffe/spire/blob/v1.15.2/doc/plugin_server_nodeattestor_x509pop.md#L88-L100). |
| Default prefix representation | `/spire-exchange` | Stored and matched as `/spire-exchange/`; configured values get a trailing slash | Use `/spire-exchange` or `/spire-exchange/`; both normalize to the same source value. Keep the leading slash. [Source](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/plugin/nodeattestor/x509pop/x509pop.go#L130-L138). |
| Empty prefix | Doc says `""` leaves all prefixes allowed | Source normalizes `""` to `/` | It remains broad for conforming absolute paths, but trimming removes the initial slash. Do not use an empty prefix for P9. [Source](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/plugin/nodeattestor/x509pop/x509pop.go#L130-L138), [doc](https://github.com/spiffe/spire/blob/v1.15.2/doc/plugin_server_nodeattestor_x509pop.md#L69-L86). |
| Agent private-key formats | Doc says PEM PKCS#1 or PKCS#8 | Actual `tls.LoadX509KeyPair` also accepts SEC1 EC; x509pop itself only supports RSA/ECDSA | PEM-wrap broker PKCS#8 DER as `PRIVATE KEY`; do not use Ed25519. [Agent doc](https://github.com/spiffe/spire/blob/v1.15.2/doc/plugin_agent_nodeattestor_x509pop.md#L14-L34), [loader](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/plugin/nodeattestor/x509pop/x509pop.go#L151-L205), [Go parser](https://github.com/golang/go/blob/go1.26.4/src/crypto/tls/tls.go#L301-L389). |
| Agent doc's identity description | Describes only fingerprint-derived external-PKI identity | SPIFFE mode trims the exchange path and uses the SVID template | Rely on the server/common source and the SPIFFE-mode server test. [Agent doc](https://github.com/spiffe/spire/blob/v1.15.2/doc/plugin_agent_nodeattestor_x509pop.md#L1-L20), [source](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/plugin/nodeattestor/x509pop/x509pop.go#L319-L365). |
| Trust bundle placement | Not an x509pop agent plugin key | Top-level `agent.trust_bundle_path`; default format `pem` | Convert all delivered DER authorities to PEM and configure the top-level agent block. [Run config](https://github.com/spiffe/spire/blob/v1.15.2/cmd/spire-agent/cli/run/run.go#L74-L104), [parser](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/trustbundlesources/bundle.go#L239-L257). |
| One-use exchange credential | Docs do not explain rotation/restart coupling | Server sets `CanReattest: true`; every re-attestation reloads and reuses x509pop credential paths | Provide a fresh tmpfs credential per re-attestation, not merely per first boot, or record rotation failure as the design finding. [Server](https://github.com/spiffe/spire/blob/v1.15.2/pkg/server/plugin/nodeattestor/x509pop/x509pop.go#L346-L365), [rotator](https://github.com/spiffe/spire/blob/v1.15.2/pkg/agent/svid/rotator.go#L190-L288). |

## P9 live-run checklist derived from source

1. Configure the server with `mode = "spiffe"` and the source key `spiffe_prefix = "/spire-exchange"`; do not set `ca_bundle_path(s)`.
2. Ensure the broker registration entry issues exactly `spiffe://spike.incus.internal/spire-exchange/incus/<instance-uuid>` from the physically attested host selector.
3. On redemption, parse and validate public certificate metadata before starting the guest agent: first URI SAN is the expected exchange ID, certificate is currently valid, `digitalSignature` is present, key is RSA or ECDSA, and the chain is leaf-first.
4. Write key, chain, and trust bundle only to the designated tmpfs directory. Key: PEM `PRIVATE KEY`; chain: leaf-first PEM `CERTIFICATE` blocks; bundle: one PEM `CERTIFICATE` block per authority. Never log bytes, encoded material, or the private-key length.
5. Configure guest `x509pop` with `private_key_path`, `certificate_path`, and only if necessary `intermediates_path`. Configure `agent.trust_bundle_path` separately with `trust_bundle_format = "pem"` or its default.
6. Start the agent with persistent `data_dir` and disk KeyManager storage if restart reuse of the node SVID is part of the experiment.
7. Confirm the created agent ID is exactly `spiffe://spike.incus.internal/spire/agent/x509pop/incus/<instance-uuid>`.
8. Inspect agent selectors. Expect CA fingerprint and serial-number selectors; do not require a selector derived from the `spiffe:` exchange URI.
9. Parent the guest workload entry on the exact guest node ID and use guest-local WorkloadAttestor selectors for the workload.
10. Exercise both restart cases separately: restart while the cached node SVID is valid, and restart/rotation after it is expired or forced to re-attest. Record that missing tmpfs exchange files can fail plugin configuration even when cached node state exists, and that expired exchange material cannot complete full re-attestation.
11. Keep exchange private material out of the transcript and journal. Evidence may contain public certificate metadata, SPIFFE IDs, fingerprints, selectors, and redacted errors only.

## Unknowns and exact settling experiments

- **No material upstream contract item above is undetermined from the pinned source.** The required file formats, prefix key, prefix trimming, template, proof algorithm, trust-bundle behavior, selectors, and re-attestation paths are all explicit in `v1.15.2` source.
- **[UNVERIFIED] Live deployment state:** this read-only task did not inspect the active server configuration. The supplied context says `svid_prefix`; if that is the literal HCL key rather than shorthand, it disagrees with the source binding. Settle this before touching the guest by running the `v1.15.2` server configuration validator against the exact sanitized P9 `server.conf`; success must be obtained with `spiffe_prefix`, and no secret material is involved.
- **[UNVERIFIED] Operational rotation timing:** source proves that rotation selects full x509pop re-attestation, but the wall-clock time depends on the issued node-SVID lifetime and configured rotation strategy. Settle the operational observation by recording the node SVID `NotAfter`, keeping the exchange files only in tmpfs, forcing or waiting for the first agent-SVID rotation, and confirming that refreshed exchange files succeed while absent/expired files fail. Record only timestamps, public certificate metadata, SPIFFE IDs, and redacted errors.