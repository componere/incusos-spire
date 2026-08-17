#!/usr/bin/env bash
#
# drive-broker.sh — P7 operator harness for the SPIRE 1.15.2 experimental
# Broker API (spiffe.broker.API) over its Unix domain socket.
#
# THROWAWAY spike tooling. Appendix C of SPIKE_PLAN.md classifies everything
# under spike/ as never merged as product code: it is deletable without loss,
# because the evidence it produces lives in the journal. Do not import, wrap, or
# promote any of this.
#
# It drives three cases and prints a verdict for each:
#
#   1. positive       SubscribeToX509SVID with the Incus reference and the
#                     mandatory header            -> an X509SVID is streamed
#   2. missing-header the same call without the header
#                                                 -> InvalidArgument
#   3. wrong-type     the same call with a type_url outside the broker's
#                     allowed_reference_types     -> PermissionDenied
#
# Reflection caveat (BROKER_BRIEF.md section 2): SPIRE 1.15.2 does register
# reflection, but only over the Unix socket, and the security-header middleware
# covers reflection too. So grpcurl needs '-rpc-header broker.spiffe.io: true'
# even to list services, and reflection over TCP answers PermissionDenied. This
# harness therefore prefers an explicit protoset over reflection: it also
# supplies the vendor IncusInstanceReference descriptor, which reflection on the
# agent cannot provide. Set PROBE_REFLECTION=1 to run the header-gated
# reflection probe as an extra, non-fatal step.
#
# Every knob below is an environment variable with a working default; the script
# never needs editing.

set -euo pipefail

# --- Parameters ---------------------------------------------------------------

# Binaries.
GRPCURL_BIN="${GRPCURL_BIN:-grpcurl}"
PROTOC_BIN="${PROTOC_BIN:-protoc}"

# Repository root, used to find the Incus reference proto.
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

# Broker endpoint and the client identity it authenticates with. SPIRE pins the
# endpoint to mutual TLS even over the Unix socket, so the certificate and key
# are mandatory. Obtain them from the host agent's Workload API first; the
# SPIFFE ID must equal a configured brokers[].id.
BROKER_SOCKET="${BROKER_SOCKET:-/run/spire/broker-sockets/broker.sock}"
BROKER_SVID_CERT_PEM="${BROKER_SVID_CERT_PEM:-/run/incus-broker/svid.pem}"
BROKER_SVID_KEY_PEM="${BROKER_SVID_KEY_PEM:-/run/incus-broker/svid-key.pem}"

# Descriptor set covering spiffe.broker.API and IncusInstanceReference. Built on
# demand when the file is absent.
PROTOSET="${PROTOSET:-/tmp/incus-broker.protoset}"
GO_SPIFFE_VERSION="${GO_SPIFFE_VERSION:-v2.8.1}"

# The reference under test. The frozen P6 type_url must match the agent's
# brokers[].allowed_reference_types[].type_url exactly.
REFERENCE_TYPE_URL="${REFERENCE_TYPE_URL:-type.googleapis.com/componere.incus.v1alpha1.IncusInstanceReference}"
INSTANCE_UUID="${INSTANCE_UUID:-e9e6a2a0-d695-42d3-8e8c-92d290bfc7da}"
INSTANCE_PROJECT="${INSTANCE_PROJECT:-spike-spiffe}"
GENERATION_UUID="${GENERATION_UUID:-74957ed8-19bc-4d23-b76b-763bb6f8bb60}"
SERVER_FINGERPRINT="${SERVER_FINGERPRINT:-822b00ed474a2574d43223cbf34919b76a64946e145ec246aa4ae2e43318afdd}"

# A type_url the broker allowlist does not contain. It is a real message in the
# Broker proto, so grpcurl can still encode the Any locally and the rejection is
# provably server-side.
WRONG_TYPE_URL="${WRONG_TYPE_URL:-type.googleapis.com/spiffe.broker.WorkloadPIDReference}"

# SubscribeToX509SVID is server-streaming and stays open for updates, so every
# call is bounded. grpcurl reports DeadlineExceeded once the bound elapses; on
# the positive case that happens after the first SVID has already printed.
MAX_TIME="${MAX_TIME:-10}"

# Optional extra step, see the reflection caveat above.
PROBE_REFLECTION="${PROBE_REFLECTION:-0}"

readonly SECURITY_HEADER='broker.spiffe.io: true'
readonly METHOD='spiffe.broker.API/SubscribeToX509SVID'

failures=0

# --- Helpers -----------------------------------------------------------------

log() {
	printf '%s\n' "$*"
}

fail() {
	printf 'ERROR: %s\n' "$*" >&2
	exit 1
}

require_tool() {
	command -v "$1" >/dev/null 2>&1 || fail "$2 not found: $1 (override with $3)"
}

require_file() {
	[[ -r "$1" ]] || fail "$2 is not readable: $1 (override with $3)"
}

# print_argv echoes a command line in a copy-pasteable, shell-quoted form.
print_argv() {
	printf '  '
	printf '%q ' "$@"
	printf '\n'
}

# incus_reference prints the request body for the allowlisted Incus reference,
# nested exactly as the Broker API requires: the Any sits inside
# WorkloadReference, which sits inside SubscribeToX509SVIDRequest.
incus_reference() {
	cat <<-JSON
		{
		  "reference": {
		    "reference": {
		      "@type": "${REFERENCE_TYPE_URL}",
		      "instanceUuid": "${INSTANCE_UUID}",
		      "project": "${INSTANCE_PROJECT}",
		      "generationUuid": "${GENERATION_UUID}",
		      "server": "${SERVER_FINGERPRINT}"
		    }
		  }
		}
	JSON
}

# wrong_reference prints a request body whose Any carries a type_url outside the
# broker's allowlist.
wrong_reference() {
	cat <<-JSON
		{
		  "reference": {
		    "reference": {
		      "@type": "${WRONG_TYPE_URL}",
		      "pid": 1
		    }
		  }
		}
	JSON
}

# build_protoset writes PROTOSET from the pinned go-spiffe Broker proto plus the
# repository's Incus reference proto. --include_imports is required for a
# reusable protoset.
build_protoset() {
	local go_spiffe_dir

	log "Building ${PROTOSET} from go-spiffe ${GO_SPIFFE_VERSION} and ${REPO_ROOT}/proto"
	require_tool "${PROTOC_BIN}" 'protoc' 'PROTOC_BIN'
	require_tool go 'go' 'PATH'
	require_tool jq 'jq' 'PATH'
	require_file "${REPO_ROOT}/proto/componere/incus/v1alpha1/reference.proto" \
		'the Incus reference proto' 'REPO_ROOT'

	go_spiffe_dir="$(cd "${REPO_ROOT}" &&
		go mod download -json "github.com/spiffe/go-spiffe/v2@${GO_SPIFFE_VERSION}" | jq -r .Dir)"
	[[ -d "${go_spiffe_dir}" ]] || fail "go mod download did not yield a go-spiffe directory"

	"${PROTOC_BIN}" \
		-I "${go_spiffe_dir}" \
		-I "${REPO_ROOT}/proto" \
		--include_imports \
		--descriptor_set_out="${PROTOSET}" \
		"${go_spiffe_dir}/exp/proto/spiffe/broker/api.proto" \
		"${REPO_ROOT}/proto/componere/incus/v1alpha1/reference.proto"
}

# set_grpcurl_argv fills GRPCURL_ARGV with the flags every case shares. The
# certificate and key are not optional: the endpoint is mutual TLS even over the
# Unix socket. -insecure only disables hostname verification of the server
# certificate, which never applies to an X.509-SVID; the server still
# authenticates this client. A production broker authorizes the server by its
# SPIFFE ID instead, as internal/broker does.
set_grpcurl_argv() {
	GRPCURL_ARGV=(
		"${GRPCURL_BIN}"
		-unix
		-insecure
		-cert "${BROKER_SVID_CERT_PEM}"
		-key "${BROKER_SVID_KEY_PEM}"
		-protoset "${PROTOSET}"
		-max-time "${MAX_TIME}"
	)
}

# run_case invokes one Broker call and judges the result.
#
#   $1 case name
#   $2 what the case proves
#   $3 extended regex the combined output must match to pass
#   $4 'header' to send the mandatory security header, 'no-header' to omit it
#   $5 name of the function producing the request body
run_case() {
	local name="$1" proves="$2" expect="$3" header_mode="$4" body_fn="$5"
	local -a argv
	local body output status=0

	set_grpcurl_argv
	argv=("${GRPCURL_ARGV[@]}")
	if [[ "${header_mode}" == 'header' ]]; then
		argv+=(-rpc-header "${SECURITY_HEADER}")
	fi
	argv+=(-d @ "${BROKER_SOCKET}" "${METHOD}")

	body="$("${body_fn}")"

	log ''
	log "=== case: ${name}"
	log "    proves: ${proves}"
	log "    expects output matching: ${expect}"
	log "--- invocation"
	print_argv "${argv[@]}"
	log "--- request body"
	printf '%s\n' "${body}"
	log "--- output (stdout and stderr, grpcurl exit code reported below)"

	output="$(printf '%s\n' "${body}" | "${argv[@]}" 2>&1)" || status=$?
	printf '%s\n' "${output}"
	log "--- grpcurl exit code: ${status}"

	if printf '%s' "${output}" | grep -Eq -- "${expect}"; then
		log "VERDICT ${name}: PASS"
	else
		log "VERDICT ${name}: FAIL (output did not match ${expect})"
		failures=$((failures + 1))
	fi
}

# probe_reflection lists services over the Unix socket. Reflection is
# header-gated, so the same header is required here; without it the agent answers
# InvalidArgument instead of a service list.
probe_reflection() {
	local -a argv
	local output status=0

	set_grpcurl_argv
	argv=("${GRPCURL_ARGV[@]}")
	argv+=(-rpc-header "${SECURITY_HEADER}" "${BROKER_SOCKET}" list)

	log ''
	log '=== extra: header-gated reflection probe (non-fatal)'
	print_argv "${argv[@]}"

	output="$("${argv[@]}" 2>&1)" || status=$?
	printf '%s\n' "${output}"
	log "--- grpcurl exit code: ${status}"
}

# --- Main --------------------------------------------------------------------

main() {
	require_tool "${GRPCURL_BIN}" 'grpcurl' 'GRPCURL_BIN'
	require_file "${BROKER_SVID_CERT_PEM}" "the broker SVID certificate" 'BROKER_SVID_CERT_PEM'
	require_file "${BROKER_SVID_KEY_PEM}" "the broker SVID private key" 'BROKER_SVID_KEY_PEM'
	[[ -S "${BROKER_SOCKET}" ]] || fail "not a socket: ${BROKER_SOCKET} (override with BROKER_SOCKET)"

	[[ -r "${PROTOSET}" ]] || build_protoset

	log "broker socket: ${BROKER_SOCKET}"
	log "protoset:      ${PROTOSET}"
	log "instance uuid: ${INSTANCE_UUID} (project ${INSTANCE_PROJECT})"

	# The stream stays open after the first SVID, so the bound elapsing with an
	# SVID already printed is the success shape. spiffeId only appears in an
	# X509SVID message.
	run_case 'positive' \
		'an allowlisted reference with the mandatory header yields an X.509-SVID' \
		'"spiffeId"' \
		'header' \
		incus_reference

	run_case 'missing-header' \
		'omitting broker.spiffe.io makes SPIRE reject the call before any attestation' \
		'code = InvalidArgument' \
		'no-header' \
		incus_reference

	run_case 'wrong-type' \
		'a type_url outside allowed_reference_types is denied before any attestor runs' \
		'code = PermissionDenied' \
		'header' \
		wrong_reference

	if [[ "${PROBE_REFLECTION}" == '1' ]]; then
		probe_reflection
	fi

	log ''
	if ((failures > 0)); then
		log "RESULT: ${failures} case(s) FAILED"
		exit 1
	fi
	log 'RESULT: all cases PASSED'
}

main "$@"
