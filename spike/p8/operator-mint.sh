#!/usr/bin/env bash
#
# operator-mint.sh — P8 operator-side harness. Asks the incus-spiffe-broker to
# mint a one-time nonce for one Incus instance UUID and reports the public part
# of the result.
#
# THROWAWAY spike tooling. Appendix C of SPIKE_PLAN.md classifies everything
# under spike/ as never merged as product code: it is deletable without loss,
# because the evidence it produces lives in the journal. Do not import, wrap, or
# promote any of this.
#
# ---------------------------------------------------------------------------
# SECRET HANDLING — Appendix D rules 1 and 5
# ---------------------------------------------------------------------------
# The whole point of the mint API is that the secret leaves the broker through
# the instance's own bootstrap configuration key and NOT through this response.
# So this script does two things about secrets:
#
#   * It never prints a response body. It prints named, non-secret fields only:
#     nonce ID, expiry, resolved instance name, generation UUID.
#   * It actively asserts that the response carries no secret field, and fails
#     loudly with exit code 20 if it does. That assertion is a live check of the
#     broker's contract, not decoration: a mint response containing the nonce
#     would move the secret onto the operator's terminal and into the run
#     transcript, which Appendix D forbids outright.
#
# An optional operator bearer token is passed through a curl --config file, so
# it never appears in argv (which is world-readable through /proc) and never in
# a log line.
#
# ---------------------------------------------------------------------------
# WIRE CONTRACT
# ---------------------------------------------------------------------------
#   POST $BROKER_URL/v1alpha1/nonce
#   {"instance_uuid": "...", "project": "...", "ttl_seconds": 120}
#
# ttl_seconds is OPTIONAL and BOUNDED. It exists for the expiry case of
# lifecycle-matrix.sh. The broker validates it and caps it at its configured
# maximum (-nonce-ttl), so the ttl that was asked for is not necessarily the ttl
# that applies: the expires_at in the response is the only authority, and this
# script always prints it. Omit MINT_TTL_SECONDS to take the broker default.
# This script sends the field only when MINT_TTL_SECONDS is set, and refuses a
# value that is not a positive integer, because the mint decoder now REJECTS
# unknown and malformed fields with HTTP 400 instead of silently dropping them.
#
#   201 (or 200) {"nonce_id": "...", "expires_at": "<RFC3339>",
#                 "instance_name": "...", "instance_uuid": "...",
#                 "generation": "...", "project": "..."}
#
# and no nonce field, ever. The resolved name and generation matter because P6
# proved instance names are reusable after delete+recreate and that a snapshot
# restore installs a fresh generation: the mint response is the operator's record
# of which instance the broker actually bound, at which generation.
#
# ---------------------------------------------------------------------------
# EXIT CODES
# ---------------------------------------------------------------------------
#   0   minted; the response carried no secret
#   2   usage or missing dependency
#   5   TLS pin failure against BROKER_FINGERPRINT
#   14  broker answered a non-2xx status (400/401/409/500/503 are diagnosed)
#   15  transport failure: no HTTP status was obtained
#   20  CONTRACT VIOLATION: the mint response carried a secret field
#   21  the response is unusable: not JSON, or no nonce_id

set -euo pipefail
umask 077

# --- Parameters ---------------------------------------------------------------

CURL_BIN="${CURL_BIN:-curl}"
JQ_BIN="${JQ_BIN:-jq}"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"

# Broker mint endpoint. This is the operator-facing side of the broker, not the
# guest-facing one, but the spike serves both from one listener.
BROKER_URL="${BROKER_URL:-https://spike-broker:8443}"
NONCE_PATH="${NONCE_PATH:-/v1alpha1/nonce}"

# Target instance. Positional arguments win over the environment.
INSTANCE_UUID="${INSTANCE_UUID:-}"
PROJECT="${PROJECT:-spike-spiffe}"

# Optional TTL request, used by the expiry case of the lifecycle matrix. Unset
# means the field is not sent at all. When set it must be a positive integer
# number of seconds; the broker caps it at its configured maximum.
MINT_TTL_SECONDS="${MINT_TTL_SECONDS:-}"

# TLS. BROKER_CACERT is the spike CA; BROKER_FINGERPRINT additionally pins the
# broker's leaf certificate exactly as the guest does from its payload.
BROKER_CACERT="${BROKER_CACERT:-}"
BROKER_FINGERPRINT="${BROKER_FINGERPRINT:-}"
BROKER_TLS_HOSTNAME="${BROKER_TLS_HOSTNAME:-}"
ALLOW_INSECURE_TLS="${ALLOW_INSECURE_TLS:-0}"

# Operator authorization. The mint endpoint requires it: the broker compares the
# presented bearer token against the digest of its -mint-token-file and answers
# 401 otherwise. The file form is preferred, because a value in the environment
# is visible to anything that reads /proc/<pid>/environ. Both are left optional
# here so the 401 refusal itself can be demonstrated.
MINT_AUTH_TOKEN_FILE="${MINT_AUTH_TOKEN_FILE:-}"
MINT_AUTH_TOKEN="${MINT_AUTH_TOKEN:-}"

CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-5}"
MAX_TIME="${MAX_TIME:-20}"

WORK_DIR=""

# --- Helpers ------------------------------------------------------------------

log() {
	printf '%s\n' "$*"
}

warn() {
	printf 'WARNING: %s\n' "$*" >&2
}

die() {
	local code="$1"
	shift
	printf 'ERROR: %s\n' "$*" >&2
	exit "$code"
}

cleanup() {
	if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
		rm -rf -- "$WORK_DIR" || true
	fi
	return 0
}

require_tool() {
	command -v "$1" >/dev/null 2>&1 || die 2 "$2 not found: $1 (override with $3)"
}

is_ip_literal() {
	[[ "$1" =~ ^[0-9]+(\.[0-9]+){3}$ || "$1" == *:* ]]
}

normalize_fingerprint() {
	printf '%s' "$1" | tr 'A-Z' 'a-z' | tr -d ': \t\n' | sed -e 's/^sha256//'
}

# json_field prints the first non-empty value among the supplied field names. The
# canonical spelling comes first; the alternates exist because a spike broker's
# field naming is not a frozen contract and the live run should still report.
json_field() {
	local file="$1"
	shift
	local names=("$@") filter=""
	local name
	for name in "${names[@]}"; do
		filter+="${filter:+, }.\"${name}\"?"
	done
	"$JQ_BIN" -r "first((${filter}) | select(. != null and . != \"\")) // \"\"" <"$file" 2>/dev/null || printf ''
}

usage() {
	cat <<'EOF'
usage: operator-mint.sh <instance-uuid> [project]

Mints one bootstrap nonce for an Incus instance UUID and prints the public part
of the mint response. Environment variables (all optional except the UUID, which
may also be given as INSTANCE_UUID):

  BROKER_URL=https://host:port   default https://spike-broker:8443
  NONCE_PATH=/v1alpha1/nonce     mint endpoint path
  PROJECT=name                   default spike-spiffe
  MINT_TTL_SECONDS=N             optional positive integer; the broker caps it
                                 at its configured maximum and the returned
                                 expires_at is authoritative. Unset: not sent
  BROKER_CACERT=PATH             spike CA for chain validation (recommended)
  BROKER_FINGERPRINT=SHA256      additionally pin the broker leaf certificate
  BROKER_TLS_HOSTNAME=NAME       certificate SAN to validate against
  ALLOW_INSECURE_TLS=1           explicit opt-in: disable chain validation
  MINT_AUTH_TOKEN_FILE=PATH      operator bearer token, read from a file
  MINT_AUTH_TOKEN=VALUE          operator bearer token, from the environment
  CURL_BIN JQ_BIN OPENSSL_BIN CONNECT_TIMEOUT MAX_TIME

The response body is never printed, and a response carrying a nonce secret is a
contract violation (exit 20).
EOF
}

# --- TLS pinning --------------------------------------------------------------

# pin_broker_certificate is the operator-side twin of the guest check: it fetches
# the leaf, compares its SHA-256 against BROKER_FINGERPRINT, and hands the SPKI
# hash of that same certificate to curl. curl cannot pin a certificate digest
# itself, only an SPKI digest, which is why openssl does the comparison.
pin_broker_certificate() {
	local host="$1" port="$2" expected="$3"

	local sni="$host"
	[[ -n "$BROKER_TLS_HOSTNAME" ]] && sni="$BROKER_TLS_HOSTNAME"

	local -a s_client=(-connect "$host:$port")
	if ! is_ip_literal "$sni"; then
		s_client+=(-servername "$sni")
	fi

	PINNED_LEAF="$WORK_DIR/broker-leaf.pem"
	"$OPENSSL_BIN" s_client "${s_client[@]}" </dev/null 2>"$WORK_DIR/s_client.err" |
		awk '/-----BEGIN CERTIFICATE-----/{n++} n==1{print} /-----END CERTIFICATE-----/{if (n==1) exit}' \
			>"$PINNED_LEAF" || true

	if [[ ! -s "$PINNED_LEAF" ]]; then
		sed -e 's/^/tls: /' "$WORK_DIR/s_client.err" >&2 || true
		log "RESULT mint outcome=error status=000 reason=no_certificate"
		die 15 "the broker at $host:$port presented no certificate"
	fi

	local observed want
	observed=$(normalize_fingerprint "$("$OPENSSL_BIN" x509 -in "$PINNED_LEAF" -noout -fingerprint -sha256 | cut -d= -f2)")
	want=$(normalize_fingerprint "$expected")
	log "tls: broker_fingerprint expected=$want observed=$observed"

	if [[ "$observed" != "$want" ]]; then
		log "RESULT mint outcome=error status=000 reason=fingerprint_mismatch"
		die 5 "broker certificate fingerprint does not match BROKER_FINGERPRINT"
	fi

	PINNED_SPKI=$("$OPENSSL_BIN" x509 -in "$PINNED_LEAF" -pubkey -noout |
		"$OPENSSL_BIN" pkey -pubin -outform der |
		"$OPENSSL_BIN" dgst -sha256 -binary |
		"$OPENSSL_BIN" enc -base64)
	log "tls: pinned SPKI sha256//$PINNED_SPKI"
}

# --- Contract assertion -------------------------------------------------------

# assert_no_secret is the live check of the broker's contract. Any scalar whose
# leaf key name is a secret name means the mint response would hand the operator
# the nonce, which defeats the entire delivery design: the secret must reach the
# guest only through user.spiffe-bootstrap, readable by that one instance.
#
# Only key PATHS are reported, never values, and the body itself is withheld.
assert_no_secret() {
	local response="$1"
	local offenders
	offenders=$("$JQ_BIN" -r '
		[paths(scalars) | join(".")]
		| map(select(test("(^|\\.)(nonce|secret|nonce_secret|nonce_value|password|token)$")))
		| join(" ")' <"$response" 2>/dev/null || printf '')

	if [[ -n "$offenders" ]]; then
		warn "CONTRACT VIOLATION: the mint response carries secret-bearing field(s): $offenders"
		warn "The mint API must return public binding metadata only; the nonce reaches the guest"
		warn "solely through user.spiffe-bootstrap. Response body withheld (Appendix D rule 1)."
		log "RESULT mint outcome=contract_violation status=$MINT_STATUS secret_fields=$offenders"
		exit 20
	fi

	log "assert: the mint response carries no nonce, secret, or token field (Appendix D rule 5 upheld)"
}

# --- Main ---------------------------------------------------------------------

main() {
	case "${1:-}" in
	-h | --help)
		usage
		exit 0
		;;
	esac

	if (($# >= 1)); then
		INSTANCE_UUID="$1"
	fi
	if (($# >= 2)); then
		PROJECT="$2"
	fi
	if (($# > 2)); then
		die 2 "unexpected argument: $3 (usage: operator-mint.sh <instance-uuid> [project])"
	fi

	[[ -n "$INSTANCE_UUID" ]] || {
		usage >&2
		die 2 "no instance UUID given"
	}

	require_tool "$CURL_BIN" curl CURL_BIN
	require_tool "$JQ_BIN" jq JQ_BIN

	WORK_DIR=$(mktemp -d)
	trap cleanup EXIT

	[[ "$BROKER_URL" == https://* ]] || die 2 "BROKER_URL is not https: $BROKER_URL"
	local host_port="${BROKER_URL#https://}"
	host_port="${host_port%%/*}"
	local host="${host_port%%:*}"
	local port="${host_port##*:}"
	[[ "$port" != "$host_port" ]] || port=443

	local request_host="$host"
	local -a connect_to=()
	if [[ -n "$BROKER_TLS_HOSTNAME" && "$BROKER_TLS_HOSTNAME" != "$host" ]]; then
		request_host="$BROKER_TLS_HOSTNAME"
		connect_to=(--connect-to "$BROKER_TLS_HOSTNAME:$port:$host:$port")
	fi

	local -a tls=()
	if [[ -n "$BROKER_FINGERPRINT" ]]; then
		require_tool "$OPENSSL_BIN" openssl OPENSSL_BIN
		pin_broker_certificate "$host" "$port" "$BROKER_FINGERPRINT"
		tls+=(--pinnedpubkey "sha256//$PINNED_SPKI")
	fi
	if [[ -n "$BROKER_CACERT" ]]; then
		[[ -r "$BROKER_CACERT" ]] || die 2 "BROKER_CACERT is not readable: $BROKER_CACERT"
		tls+=(--cacert "$BROKER_CACERT")
	elif [[ "$ALLOW_INSECURE_TLS" == "1" ]]; then
		tls+=(--insecure)
		warn "ALLOW_INSECURE_TLS=1: curl chain and hostname validation are DISABLED for this request."
		warn "Record that in the evidence, and prefer BROKER_CACERT plus BROKER_FINGERPRINT."
	elif [[ -n "$PINNED_LEAF" ]]; then
		tls+=(--cacert "$PINNED_LEAF")
		log "mint: using the pinned leaf as its own trust anchor (self-signed broker certificate)"
	else
		die 2 "no way to validate the broker TLS certificate: set BROKER_CACERT, or BROKER_FINGERPRINT, or ALLOW_INSECURE_TLS=1"
	fi

	# The bearer token, when present, travels through a curl config file so it
	# never lands in argv.
	local -a config=()
	local token=""
	if [[ -n "$MINT_AUTH_TOKEN_FILE" ]]; then
		[[ -r "$MINT_AUTH_TOKEN_FILE" ]] || die 2 "MINT_AUTH_TOKEN_FILE is not readable: $MINT_AUTH_TOKEN_FILE"
		token=$(tr -d '\r\n' <"$MINT_AUTH_TOKEN_FILE")
	elif [[ -n "$MINT_AUTH_TOKEN" ]]; then
		token="$MINT_AUTH_TOKEN"
	fi
	if [[ -n "$token" ]]; then
		printf 'header = "Authorization: Bearer %s"\n' "$token" >"$WORK_DIR/curl.conf"
		config=(--config "$WORK_DIR/curl.conf")
		token=""
		log "mint: sending an operator bearer token (value withheld)"
	else
		# Not fatal: minting without a credential is exactly how the 401 refusal
		# is demonstrated. It is announced so a 401 below is not a mystery.
		warn "no operator bearer token configured (MINT_AUTH_TOKEN_FILE or MINT_AUTH_TOKEN)."
		warn "The mint endpoint is authenticated, so expect HTTP 401 unless you are testing that refusal."
	fi

	# The body carries exactly the fields the mint API defines. ttl_seconds is
	# sent ONLY when the operator asked for one: the broker rejects unknown or
	# malformed fields with HTTP 400, and a bare --argjson would happily splice
	# whatever MINT_TTL_SECONDS contained into the request.
	local body
	if [[ -n "$MINT_TTL_SECONDS" ]]; then
		[[ "$MINT_TTL_SECONDS" =~ ^[1-9][0-9]*$ ]] ||
			die 2 "MINT_TTL_SECONDS must be a positive integer number of seconds, got: $MINT_TTL_SECONDS"
		body=$("$JQ_BIN" -cn --arg uuid "$INSTANCE_UUID" --arg project "$PROJECT" \
			--argjson ttl "$MINT_TTL_SECONDS" \
			'{instance_uuid: $uuid, project: $project, ttl_seconds: $ttl}')
	else
		body=$("$JQ_BIN" -cn --arg uuid "$INSTANCE_UUID" --arg project "$PROJECT" \
			'{instance_uuid: $uuid, project: $project}')
	fi

	local url="https://$request_host:$port$NONCE_PATH"
	log "mint: POST $url"
	log "mint: instance_uuid=$INSTANCE_UUID project=$PROJECT ttl_seconds=${MINT_TTL_SECONDS:-<not sent: broker default>}"

	local response="$WORK_DIR/response"
	set +e
	MINT_STATUS=$(printf '%s' "$body" | "$CURL_BIN" --silent --show-error \
		--request POST \
		--header 'Content-Type: application/json' \
		--data-binary @- \
		--connect-timeout "$CONNECT_TIMEOUT" \
		--max-time "$MAX_TIME" \
		"${tls[@]}" "${connect_to[@]+"${connect_to[@]}"}" "${config[@]+"${config[@]}"}" \
		--output "$response" \
		--write-out '%{http_code}' \
		"$url" 2>"$WORK_DIR/curl.err")
	local rc=$?
	set -e

	if ((rc != 0)) || [[ -z "$MINT_STATUS" || "$MINT_STATUS" == "000" ]]; then
		sed -e 's/^/mint: /' "$WORK_DIR/curl.err" >&2 || true
		log "RESULT mint outcome=error status=000 reason=transport_failure"
		die 15 "no HTTP status from $url; check BROKER_CACERT, BROKER_TLS_HOSTNAME, and that the broker is listening"
	fi

	log "mint: HTTP $MINT_STATUS"

	# The assertion runs before anything else is read out of the body, and on
	# every status: an error path is exactly where a careless broker would echo
	# the nonce it just minted.
	assert_no_secret "$response"

	case "$MINT_STATUS" in
	200 | 201) ;;
	401)
		log "verdict: REJECTED 401 — the mint endpoint refused this operator credential."
		log "RESULT mint outcome=rejected status=401 reason=$(json_field "$response" error reason message)"
		exit 14
		;;
	404)
		log "verdict: REJECTED 404 — the endpoint path does not exist. Check NONCE_PATH; the broker"
		log "         answers 409, not 404, when a UUID does not resolve."
		log "RESULT mint outcome=rejected status=404 reason=$(json_field "$response" error reason message)"
		exit 14
		;;
	409)
		log "verdict: REJECTED 409 conflict — the broker refused to bind instance_uuid=$INSTANCE_UUID in"
		log "         project=$PROJECT. Either the UUID did not resolve to exactly one live instance, or"
		log "         its state forbids minting. P5: only the read-only attestor credential can resolve a"
		log "         UUID to a name, so a 409 here often means that credential or the project is wrong."
		log "RESULT mint outcome=rejected status=409 reason=$(json_field "$response" error reason message)"
		exit 14
		;;
	400)
		log "verdict: REJECTED 400 invalid request — the broker could not accept the body. The mint"
		log "         decoder is strict: an unknown field, a malformed UUID, or a ttl_seconds outside"
		log "         the permitted bound is a 400, not a silently ignored value. Check"
		log "         MINT_TTL_SECONDS=${MINT_TTL_SECONDS:-<not sent>} against the broker's maximum."
		log "RESULT mint outcome=rejected status=400 reason=$(json_field "$response" error reason message)"
		exit 14
		;;
	500)
		log "verdict: ERROR 500 — broker internal failure while minting."
		log "RESULT mint outcome=error status=500 reason=$(json_field "$response" error reason message)"
		exit 14
		;;
	503)
		log "verdict: ERROR 503 — a broker dependency is unavailable: the nonce store, the read-only"
		log "         Incus credential that resolves the UUID, or the bootstrap-writer credential that"
		log "         writes user.spiffe-bootstrap. P5 keeps those two credentials separate."
		log "RESULT mint outcome=error status=503 reason=$(json_field "$response" error reason message)"
		exit 14
		;;
	*)
		log "verdict: UNEXPECTED $MINT_STATUS"
		log "RESULT mint outcome=error status=$MINT_STATUS reason=$(json_field "$response" error reason message)"
		exit 14
		;;
	esac

	if ! "$JQ_BIN" -e 'type == "object"' >/dev/null 2>&1 <"$response"; then
		log "RESULT mint outcome=error status=$MINT_STATUS reason=response_not_json"
		die 21 "the mint response is not a JSON object (body withheld)"
	fi

	local nonce_id expires_at instance_name generation_uuid resolved_uuid resolved_project
	nonce_id=$(json_field "$response" nonce_id id)
	expires_at=$(json_field "$response" expires_at expiry expires)
	instance_name=$(json_field "$response" instance_name name)
	generation_uuid=$(json_field "$response" generation_uuid generation)
	resolved_uuid=$(json_field "$response" instance_uuid uuid)
	resolved_project=$(json_field "$response" project)

	log "minted:"
	log "  nonce_id=${nonce_id:-<absent>}"
	log "  expires_at=${expires_at:-<absent>}${MINT_TTL_SECONDS:+ (requested ttl_seconds=$MINT_TTL_SECONDS; the applied TTL is whatever the broker bound allowed)}"
	log "  instance_name=${instance_name:-<absent>}"
	log "  generation_uuid=${generation_uuid:-<absent>}"
	log "  instance_uuid=${resolved_uuid:-<absent>}"
	log "  project=${resolved_project:-<absent>}"
	log "  nonce=<never returned by this API; it reaches the guest through user.spiffe-bootstrap>"

	if [[ -z "$nonce_id" ]]; then
		log "RESULT mint outcome=error status=$MINT_STATUS reason=missing_nonce_id"
		die 21 "the mint response has no nonce_id, so nothing can be redeemed or correlated"
	fi

	if [[ -n "$resolved_uuid" && "$resolved_uuid" != "$INSTANCE_UUID" ]]; then
		warn "the broker bound a different UUID than requested: asked $INSTANCE_UUID, got $resolved_uuid"
	fi

	if [[ -z "$instance_name" || -z "$generation_uuid" ]]; then
		warn "the response omitted the resolved name or generation. P6 proved names are reusable after"
		warn "delete+recreate and that a snapshot restore installs a fresh generation, so a mint record"
		warn "without both is not enough to interpret a later rejection."
	fi

	log "RESULT mint outcome=minted status=$MINT_STATUS nonce_id=$nonce_id expires_at=${expires_at:--} instance_name=${instance_name:--} generation_uuid=${generation_uuid:--} instance_uuid=${resolved_uuid:--} project=${resolved_project:--}"
}

MINT_STATUS="000"
PINNED_LEAF=""
PINNED_SPKI=""

main "$@"
